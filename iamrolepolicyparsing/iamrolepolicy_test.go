package iamrolepolicyparsing

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestIamRolePolicy_EqualsIfEqual(t *testing.T) {
	stringToStringPtr := func(s string) *string {
		return &s
	}
	pd1 := IamRolePolicy{
		PolicyName: stringToStringPtr("123"),
		PolicyDocument: &PolicyDocument{
			Version:    stringToStringPtr("1"),
			Id:         stringToStringPtr("2"),
			Statements: &[]Statement{},
		},
	}
	pd2 := IamRolePolicy{
		PolicyName: stringToStringPtr("123"),
		PolicyDocument: &PolicyDocument{
			Version:    stringToStringPtr("1"),
			Id:         stringToStringPtr("2"),
			Statements: &[]Statement{},
		},
	}
	if !pd1.Equals(pd2) {
		t.Errorf("Expected true, got false")
	}

}

func TestIamRolePolicy_EqualsIfSame(t *testing.T) {
	stringToStringPtr := func(s string) *string {
		return &s
	}
	pd := IamRolePolicy{
		PolicyName: stringToStringPtr("123"),
		PolicyDocument: &PolicyDocument{
			Version:    stringToStringPtr("1"),
			Id:         stringToStringPtr("2"),
			Statements: &[]Statement{},
		},
	}
	if !pd.Equals(pd) {
		t.Errorf("Expected true, got false")
	}
}

func TestIamRolePolicy_EqualsIfDifferentPolicyDocuments(t *testing.T) {
	stringToStringPtr := func(s string) *string {
		return &s
	}
	pd1 := IamRolePolicy{
		PolicyName: stringToStringPtr("1234"),
		PolicyDocument: &PolicyDocument{
			Version:    stringToStringPtr("1"),
			Id:         stringToStringPtr("2"),
			Statements: &[]Statement{},
		},
	}
	pd2 := IamRolePolicy{
		PolicyName: stringToStringPtr("123"),
		PolicyDocument: &PolicyDocument{
			Version:    stringToStringPtr("1"),
			Id:         stringToStringPtr("2"),
			Statements: &[]Statement{},
		},
	}
	if !pd1.Equals(pd2) {
		t.Errorf("Expected true, got false")
	}
}

func TestIamRolePolicy_EqualsIfDifferentVersions(t *testing.T) {
	stringToStringPtr := func(s string) *string {
		return &s
	}
	pd1 := IamRolePolicy{
		PolicyName: stringToStringPtr("1234"),
		PolicyDocument: &PolicyDocument{
			Version:    stringToStringPtr("1"),
			Id:         stringToStringPtr("2"),
			Statements: &[]Statement{},
		},
	}
	pd2 := IamRolePolicy{
		PolicyName: stringToStringPtr("123"),
		PolicyDocument: &PolicyDocument{
			Version:    stringToStringPtr("1"),
			Id:         stringToStringPtr("2"),
			Statements: &[]Statement{},
		},
	}
	if !pd1.Equals(pd2) {
		t.Errorf("Expected true, got false")
	}
}

func TestIamRolePolicy_EqualsIfOtherNull(t *testing.T) {
	stringToStringPtr := func(s string) *string {
		return &s
	}
	pd := IamRolePolicy{
		PolicyName: stringToStringPtr("123"),
		PolicyDocument: &PolicyDocument{
			Version:    stringToStringPtr("1"),
			Id:         stringToStringPtr("2"),
			Statements: &[]Statement{},
		},
	}
	if pd.Equals(nil) {
		t.Errorf("Expected true, got false")
	}
}

func TestIamRolePolicy_String(t *testing.T) {
	stringToStringPtr := func(s string) *string {
		return &s
	}
	policy := IamRolePolicy{
		PolicyName: stringToStringPtr("123"),
		PolicyDocument: &PolicyDocument{
			Version:    stringToStringPtr("1"),
			Id:         stringToStringPtr("2"),
			Statements: &[]Statement{},
		},
	}
	expected := "IamRolePolicy{PolicyDocument: PolicyDocument{Version: 1, Id: 2, Statements: []}, PolicyName: 123}"
	if policy.String() != expected {
		t.Errorf("Expected %s, got %s", expected, policy.String())
	}
}

func TestUnmarshal_IamRolePolicyWhenNull(t *testing.T) {
	stringToStringPtr := func(s string) *string { return &s }
	data := `null`
	policy := IamRolePolicy{
		PolicyName: stringToStringPtr("123"),
		PolicyDocument: &PolicyDocument{
			Version:    stringToStringPtr("1"),
			Id:         stringToStringPtr("2"),
			Statements: &[]Statement{},
		},
	}
	original := IamRolePolicy{
		PolicyName: stringToStringPtr("123"),
		PolicyDocument: &PolicyDocument{
			Version:    stringToStringPtr("1"),
			Id:         stringToStringPtr("2"),
			Statements: &[]Statement{},
		},
	}

	err := json.Unmarshal([]byte(data), &policy)

	if !policy.Equals(original) {
		t.Errorf("Expected Unmarshalling to be a noop")
	}
	if err != nil {
		t.Errorf(`Expected Unmarshalling a "null" to be not throw an error`)
	}
}

func TestUnmarshal_IamRolePolicy(t *testing.T) {
	data := `{"PolicyName": "policyName", "PolicyDocument":{"Version": "2008-10-17", "Id": "i2d", "Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":["arn:aws:iam::123456789012:user/JohnDoe"]},"NotAction":"s3:ListBucket","Resource":["arn:aws:s3:::example-bucket"]}]}}`
	var iamRolePolicy IamRolePolicy
	err := json.Unmarshal([]byte(data), &iamRolePolicy)
	// todo compare against wanted

	if err != nil {
		t.Errorf("Expected error: <nil>, got: %v", err.Error())
	}
}

func TestUnmarshal_IamRolePolicyWhenMissingPolicyName(t *testing.T) {
	data := `{"PolicyDocument":{"Version": "2008-10-17", "Id": "i2d", "Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":["arn:aws:iam::123456789012:user/JohnDoe"]},"NotAction":"s3:ListBucket","Resource":["arn:aws:s3:::example-bucket"]}]}}`
	var iamRolePolicy IamRolePolicy
	err := json.Unmarshal([]byte(data), &iamRolePolicy)
	expectedErr := errors.New("PolicyName is required")

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %s, got: %s", expectedErr.Error(), err.Error())
	}

}

func TestUnmarshal_IamRolePolicyWhenMissingPolicyDocument(t *testing.T) {
	data := `{"PolicyName": "policyName"}`
	var iamRolePolicy IamRolePolicy
	err := json.Unmarshal([]byte(data), &iamRolePolicy)
	expectedErr := errors.New("PolicyDocument is required")

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %s, got: %s", expectedErr.Error(), err.Error())
	}
}

func TestUnmarshal_IamRolePolicyWhenMissingPolicyNameIsArray(t *testing.T) {
	data := `{"PolicyName": [1,2], "PolicyDocument":{"Version": "2008-10-17", "Id": "i2d", "Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":["arn:aws:iam::123456789012:user/JohnDoe"]},"NotAction":"s3:ListBucket","Resource":["arn:aws:s3:::example-bucket"]}]}}`
	var iamRolePolicy IamRolePolicy
	err := json.Unmarshal([]byte(data), &iamRolePolicy)
	expectedErr := errors.New("error unmarshalling a policy: json: cannot unmarshal array into Go struct field .PolicyName of type string")

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %s, got: %s", expectedErr.Error(), err.Error())
	}
}

func TestUnmarshal_IamRolePolicyWithInvalidJSON(t *testing.T) {
	data := `1nval1d`
	var iamRolePolicy IamRolePolicy
	err := json.Unmarshal([]byte(data), &iamRolePolicy)
	expectedErr := errors.New("invalid character 'n' after top-level value")

	if expectedErr.Error() != err.Error() {
		t.Errorf("Expected error: %s, got: %s", expectedErr.Error(), err.Error())
	}
}

func TestUnmarshal_IamRolePolicyWhenCouldNotParsePolicyDocument(t *testing.T) {
	data := `{"PolicyName": 123, "PolicyDocument":{"Version": "2004-10-17", "Id": "i2d", "Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":["arn:aws:iam::123456789012:user/JohnDoe"]},"NotAction":"s3:ListBucket","Resource":["arn:aws:s3:::example-bucket"]}]}}`
	var iamRolePolicy IamRolePolicy
	err := json.Unmarshal([]byte(data), &iamRolePolicy)
	expectedErr := errors.New("error unmarshalling a policy: Version must be 2012-10-17 or 2008-10-17")

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %s, got: %s", expectedErr.Error(), err.Error())
	}
}