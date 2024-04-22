package iamrolepolicyparsing

import (
	"encoding/json"
	"errors"
	"fmt"
)

/**
 * IamRolePolicy struct represents a policy in an IAM role.
 *
 * for grammar see https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
 * see policydocument.go for the PolicyDocument struct
 */
type IamRolePolicy struct {
	PolicyDocument *PolicyDocument `json:"PolicyDocument"`
	PolicyName     *string         `json:"PolicyName"`
}

func (this IamRolePolicy) String() string {
	return "IamRolePolicy{PolicyDocument: " + this.PolicyDocument.String() + ", PolicyName: " + *this.PolicyName + "}"
}

func (this IamRolePolicy) Equals(other interface{}) bool {
	that, ok := other.(IamRolePolicy)
	if !ok {
		return false
	}
	return (this.PolicyName == that.PolicyName || *this.PolicyName == *this.PolicyName) &&
		(this.PolicyDocument == that.PolicyDocument || (*this.PolicyDocument).Equals(*that.PolicyDocument))
}

func (policy *IamRolePolicy) UnmarshalJSON(data []byte) error {
	// decode.go/line 117
	// By convention, to approximate the behavior of [Unmarshal] itself,
	// Unmarshalers implement UnmarshalJSON([]byte("null")) as a no-op.
	if string(data) == "null" {
		return nil
	}

	var statMap map[string]interface{}
	err := json.Unmarshal(data, &statMap)
	if err != nil {
		return err
	}

	// Ensure no unwanted properties exist in data
	for key, _ := range statMap {
		if key != "PolicyName" && key != "PolicyDocument" {
			// todo test
			return errors.New(fmt.Sprintf("unknown key: %s", key))
		}
	}

	// Unmarshal the JSON using the default Unmarshaler
	type Alias IamRolePolicy
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(policy),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return errors.New(fmt.Sprintf("error unmarshalling a policy: %s", err.Error()))
	}

	if policy.PolicyDocument == nil {
		return errors.New("PolicyDocument is required")
	}
	if policy.PolicyName == nil {
		return errors.New("PolicyName is required")
	}

	return nil
}

/**
 * Returns whether the policy has a statement with a resource that is a wildcard ('*').
 *
 * see (stat Statement)isResourceAWildcard() bool in statement.go
 */
func (policy IamRolePolicy) HasAStatementResourceAWildcard() bool {
	for _, statement := range *policy.PolicyDocument.Statements {
		if statement.isResourceAWildcard() {
			return true
		}
	}
	return false
}
