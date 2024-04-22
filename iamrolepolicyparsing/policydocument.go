package iamrolepolicyparsing

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

/**
 * PolicyDocument struct represents the policy document in an IAM role policy.
 *
 * for grammar see https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
 * see statement.go for the Statement struct
 */
type PolicyDocument struct {
	Version    *string      `json:"Version"`
	Id         *string      `json:"Id"`
	Statements *[]Statement `json:"Statement"`
}

func (pd *PolicyDocument) String() string {
	var statements []string
	if pd.Statements != nil {
		for _, statement := range *pd.Statements {
			statements = append(statements, statement.String())
		}
	}

	stringPtrToString := func(ptr *string) string {
		if ptr == nil {
			return "nil"
		}
		return *ptr
	}
	return fmt.Sprintf(
		"PolicyDocument{Version: %s, Id: %s, Statements: %v}",
		stringPtrToString(pd.Version),
		stringPtrToString(pd.Id),
		statements,
	)
}

func (this PolicyDocument) Equals(other interface{}) bool {
	that, ok := other.(PolicyDocument)
	if !ok || !reflect.DeepEqual(this.Version, that.Version) || !reflect.DeepEqual(this.Id, that.Id) {
		return false
	}
	if this.Statements == nil || that.Statements == nil {
		// checks types of NILs
		return this.Statements == that.Statements
	}
	if len(*this.Statements) != len(*that.Statements) {
		return false
	}
	for i, thisStatement := range *this.Statements {
		if !thisStatement.Equals((*that.Statements)[i]) {
			return false
		}
	}
	return true
}

func (pd *PolicyDocument) UnmarshalJSON(data []byte) error {
	// decode.go/line 117
	// By convention, to approximate the behavior of [Unmarshal] itself,
	// Unmarshalers implement UnmarshalJSON([]byte("null")) as a no-op.
	if string(data) == "null" {
		return nil
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	// Verify that the JSON object has only the expected keys
	for key := range m {
		switch key {
		case "Version", "Id", "Statement":
			continue
		default:
			return fmt.Errorf("unexpected key in JSON: %s", key)
		}
	}

	// Unmarshal the JSON using the default Unmarshaler
	type Alias PolicyDocument
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(pd),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return errors.New(fmt.Sprintf("error unmarshalling a statement: %s", err.Error()))
	}

	if pd.Version != nil && *pd.Version != "2012-10-17" && *pd.Version != "2008-10-17" {
		return errors.New("Version must be 2012-10-17 or 2008-10-17")
	}
	if pd.Statements == nil {
		return errors.New("Statements array is required")
	}

	return nil
}
