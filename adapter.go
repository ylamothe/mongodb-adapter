// Copyright 2018 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mongodbadapter

import (
	"context"
	"errors"
	"log"
	"runtime"

	"github.com/casbin/casbin/model"
	"github.com/casbin/casbin/persist"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// CasbinRule represents a rule in Casbin.
type CasbinRule struct {
	PType string
	V0    string
	V1    string
	V2    string
	V3    string
	V4    string
	V5    string
}

// adapter represents the MongoDB adapter for policy storage.
type adapter struct {
	client       *mongo.Client
	collection   *mongo.Collection
	databaseName string
	filtered     bool
}

// DBName sets the name of the database to be used by casbin
func DBName(databaseName string) func(*adapter) {
	return func(a *adapter) {
		a.databaseName = databaseName
	}
}

// Filtered sets flags for filtered policy
func Filtered(filtered bool) func(*adapter) {
	return func(a *adapter) {
		a.filtered = filtered
	}
}

// finalizer is the destructor for adapter.
func finalizer(a *adapter) {
	a.close()
}

// NewAdapter is the constructor for Adapter.
func NewAdapter(url string, opts ...func(*adapter)) persist.Adapter {
	cl, err := mongo.NewClient(options.Client().ApplyURI(url))

	if err != nil {
		panic(err)
	}
	a := &adapter{client: cl, filtered: false, databaseName: "casbin"}

	for _, opt := range opts {
		opt(a)
	}

	// Open the DB, create it if not existed.
	a.open()

	// Call the destructor when the object is released
	runtime.SetFinalizer(a, finalizer)

	return a

}

// NewAdapterFromClient creates a new adapter from an existing connected mongodb client.
// Intended for reusing an already established client connection.
// Opening and Closing client connection will not be handled by the adapter.
func NewAdapterFromClient(cl *mongo.Client, opts ...func(*adapter)) persist.Adapter {
	a := &adapter{client: cl, filtered: false, databaseName: "casbin"}

	for _, opt := range opts {
		opt(a)
	}

	a.prep()

	return a
}

// NewFilteredAdapter is the constructor for FilteredAdapter.
// Casbin will not automatically call LoadPolicy() for a filtered adapter.
func NewFilteredAdapter(url string, opts ...func(*adapter)) persist.FilteredAdapter {
	a := NewAdapter(url, opts...).(*adapter)
	a.filtered = true
	return a
}

func (a *adapter) open() {
	ctx := context.TODO()
	err := a.client.Connect(ctx)

	if err != nil {
		panic(err)
	}

	a.prep()

}

func (a *adapter) prep() {
	db := a.client.Database(a.databaseName)
	collection := db.Collection("casbin_rule")
	a.collection = collection

	// iview := collection.Indexes()

	// indexes := []string{"ptype", "v0", "v1", "v2", "v3", "v4", "v5"}
	// ctx := context.TODO()

	// for _, k := range indexes {
	// 	iModel := mongo.IndexModel{Keys: bsonx.Doc{{k, bsonx.Int32(1)}}}
	// 	if _, err := iview.CreateOne(ctx, iModel); err != nil {
	// 		panic(err)
	// 	}
	// }
}

// close disconnects the mongodb client. Called as a finalizer
func (a *adapter) close() {
	a.client.Disconnect(context.TODO())
}

func (a *adapter) dropTable() error {
	err := a.collection.Drop(context.TODO())

	return err
}

func loadPolicyLine(line CasbinRule, model model.Model) {
	key := line.PType
	sec := key[:1]

	tokens := []string{}
	if line.V0 != "" {
		tokens = append(tokens, line.V0)
	} else {
		goto LineEnd
	}

	if line.V1 != "" {
		tokens = append(tokens, line.V1)
	} else {
		goto LineEnd
	}

	if line.V2 != "" {
		tokens = append(tokens, line.V2)
	} else {
		goto LineEnd
	}

	if line.V3 != "" {
		tokens = append(tokens, line.V3)
	} else {
		goto LineEnd
	}

	if line.V4 != "" {
		tokens = append(tokens, line.V4)
	} else {
		goto LineEnd
	}

	if line.V5 != "" {
		tokens = append(tokens, line.V5)
	} else {
		goto LineEnd
	}

LineEnd:
	model[sec][key].Policy = append(model[sec][key].Policy, tokens)
}

// LoadPolicy loads policy from database.
func (a *adapter) LoadPolicy(model model.Model) error {
	return a.LoadFilteredPolicy(model, nil)
}

// LoadFilteredPolicy loads matching policy lines from database. If not nil,
// the filter must be a valid MongoDB selector.
func (a *adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	if filter == nil {
		filter = bson.D{}
		a.filtered = false
	} else {
		a.filtered = true
	}

	ctx := context.TODO()

	cur, err := a.collection.Find(ctx, filter)
	if err != nil {
		log.Fatal(err)
	}

	for cur.Next(ctx) {
		var line = CasbinRule{}
		if err := cur.Decode(&line); err == nil {
			loadPolicyLine(line, model)
		}

	}

	return cur.Close(ctx)
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *adapter) IsFiltered() bool {
	return a.filtered
}

func savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{
		PType: ptype,
	}

	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return line
}

// SavePolicy saves policy to database.
func (a *adapter) SavePolicy(model model.Model) error {
	if a.filtered {
		return errors.New("cannot save a filtered policy")
	}
	if err := a.dropTable(); err != nil {
		return err
	}

	var lines []interface{}

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, &line)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, &line)
		}
	}

	ctx := context.TODO()
	_, err := a.collection.InsertMany(ctx, lines)
	return err
}

// AddPolicy adds a policy rule to the storage.
func (a *adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)

	ctx := context.TODO()
	_, err := a.collection.InsertOne(ctx, line)
	return err
}

// RemovePolicy removes a policy rule from the storage.
func (a *adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)

	ctx := context.TODO()
	_, err := a.collection.DeleteOne(ctx, line)
	return err
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	selector := make(map[string]interface{})
	selector["ptype"] = ptype

	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		if fieldValues[0-fieldIndex] != "" {
			selector["v0"] = fieldValues[0-fieldIndex]
		}
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		if fieldValues[1-fieldIndex] != "" {
			selector["v1"] = fieldValues[1-fieldIndex]
		}
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		if fieldValues[2-fieldIndex] != "" {
			selector["v2"] = fieldValues[2-fieldIndex]
		}
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		if fieldValues[3-fieldIndex] != "" {
			selector["v3"] = fieldValues[3-fieldIndex]
		}
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		if fieldValues[4-fieldIndex] != "" {
			selector["v4"] = fieldValues[4-fieldIndex]
		}
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		if fieldValues[5-fieldIndex] != "" {
			selector["v5"] = fieldValues[5-fieldIndex]
		}
	}

	ctx := context.TODO()
	_, err := a.collection.DeleteMany(ctx, selector)
	return err
}
