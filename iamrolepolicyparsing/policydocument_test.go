package iamrolepolicyparsing

import (
	"errors"
	"reflect"
	"testing"
)

func stringToStringPtr(s string) *string {
	return &s
}

func TestPolicyDocument_EqualsIfSame(t *testing.T) {
	pd := PolicyDocument{
		Version: stringToStringPtr("2012-10-17"),
		Id:      stringToStringPtr("id"),
		Statements: &[]Statement{Statement{
			Effect:         stringToStringPtr("Allow"),
			Principal:      false,
			Action:         false,
			Resource:       true,
			PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
			ActionValue:    "s3:ListBucket",
			ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
		}},
	}
	if !pd.Equals(pd) {
		t.Errorf("Expected true, got false")
	}
}

func TestPolicyDocument_EqualsIfEqual(t *testing.T) {
	pd1 := PolicyDocument{
		Version: stringToStringPtr("2012-10-17"),
		Id:      stringToStringPtr("id"),
		Statements: &[]Statement{Statement{
			Effect:         stringToStringPtr("Allow"),
			Principal:      false,
			Action:         false,
			Resource:       true,
			PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
			ActionValue:    "s3:ListBucket",
			ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
		}},
	}
	pd2 := PolicyDocument{
		Version: stringToStringPtr("2012-10-17"),
		Id:      stringToStringPtr("id"),
		Statements: &[]Statement{Statement{
			Effect:         stringToStringPtr("Allow"),
			Principal:      false,
			Action:         false,
			Resource:       true,
			PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
			ActionValue:    "s3:ListBucket",
			ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
		}},
	}
	if !pd1.Equals(pd2) {
		t.Errorf("Expected true, got false")
	}
}

func TestPolicyDocument_EqualsIfNotEqualSizeOfStatements(t *testing.T) {
	pd1 := PolicyDocument{
		Version: stringToStringPtr("2012-10-17"),
		Id:      stringToStringPtr("id"),
		Statements: &[]Statement{Statement{
			Effect:         stringToStringPtr("Allow"),
			Principal:      false,
			Action:         false,
			Resource:       true,
			PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
			ActionValue:    "s3:ListBucket",
			ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
		}},
	}
	pd2 := PolicyDocument{
		Version: stringToStringPtr("2012-10-17"),
		Id:      stringToStringPtr("id"),
		Statements: &[]Statement{Statement{
			Effect:         stringToStringPtr("Allow"),
			Principal:      false,
			Action:         false,
			Resource:       true,
			PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
			ActionValue:    "s3:ListBucket",
			ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
		}, Statement{
			Effect:         stringToStringPtr("Allow"),
			Principal:      false,
			Action:         false,
			Resource:       true,
			PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
			ActionValue:    "s3:ListBucket",
			ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
		}},
	}
	if pd1.Equals(pd2) {
		t.Errorf("Expected false, got true")
	}
}

func TestPolicyDocument_EqualsIfNotEqualStatements(t *testing.T) {
	pd1 := PolicyDocument{
		Version: stringToStringPtr("2012-10-17"),
		Id:      stringToStringPtr("id"),
		Statements: &[]Statement{Statement{
			Effect:         stringToStringPtr("Allow"),
			Principal:      false,
			Action:         false,
			Resource:       true,
			PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
			ActionValue:    "s3:ListBucket",
			ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
		}},
	}
	pd2 := PolicyDocument{
		Version: stringToStringPtr("2012-10-17"),
		Id:      stringToStringPtr("id"),
		Statements: &[]Statement{Statement{
			Effect:         stringToStringPtr("Deny"),
			Principal:      false,
			Action:         false,
			Resource:       true,
			PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
			ActionValue:    "s3:ListBucket",
			ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
		}},
	}
	if pd1.Equals(pd2) {
		t.Errorf("Expected false, got true")
	}
}

func TestPolicyDocument_EqualsIfNotEqualVersions(t *testing.T) {
	pd1 := PolicyDocument{
		Version: stringToStringPtr("2012-10-17"),
		Id:      stringToStringPtr("id"),
		Statements: &[]Statement{Statement{
			Effect:         stringToStringPtr("Allow"),
			Principal:      false,
			Action:         false,
			Resource:       true,
			PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
			ActionValue:    "s3:ListBucket",
			ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
		}},
	}
	pd2 := PolicyDocument{
		Version: stringToStringPtr("2012-10-18"),
		Id:      stringToStringPtr("id"),
		Statements: &[]Statement{Statement{
			Effect:         stringToStringPtr("Allow"),
			Principal:      false,
			Action:         false,
			Resource:       true,
			PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
			ActionValue:    "s3:ListBucket",
			ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
		}},
	}
	if pd1.Equals(pd2) {
		t.Errorf("Expected false, got true")
	}
}

func TestPolicyDocument_EqualsIfOtherIsNil(t *testing.T) {
	pd := PolicyDocument{
		Version: stringToStringPtr("2012-10-17"),
		Id:      stringToStringPtr("id"),
		Statements: &[]Statement{Statement{
			Effect:         stringToStringPtr("Allow"),
			Principal:      false,
			Action:         false,
			Resource:       true,
			PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
			ActionValue:    "s3:ListBucket",
			ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
		}},
	}
	if pd.Equals(nil) {
		t.Errorf("Expected false, got true")
	}
}

func TestPolicyDocument_String(t *testing.T) {
	pd := PolicyDocument{
		Version: stringToStringPtr("2012-10-17"),
		Id:      stringToStringPtr("id"),
		Statements: &[]Statement{Statement{
			Effect:         stringToStringPtr("Allow"),
			Principal:      false,
			Action:         false,
			Resource:       true,
			PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
			ActionValue:    "s3:ListBucket",
			ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
		}},
	}
	expected := "PolicyDocument{Version: 2012-10-17, Id: id, Statements: [Statement{Sid: nil, PrincipalValue: map[AWS:[arn:aws:iam::123456789012:user/JohnDoe]], Principal: false, ActionValue: s3:ListBucket, Action: false, ResourceValue: [arn:aws:s3:::example-bucket], Resource: true, Effect: Allow, ConditionMap: <nil>}]}"
	if pd.String() != expected {
		t.Errorf("Expected: \n%s\n\t, got: \n%s", expected, pd.String())
	}
}

func TestPolicyDocument_UnmarshalJSONNoEffectInAStatement(t *testing.T) {
	data := []byte(`{"Version":"2012-10-17","Id":"id","Statement":[{"Action":"s3:ListBucket","Resource":"arn:aws:s3:::example-bucket"},{"Action":"s3:ListBucket","Resource":"arn:aws:s3:::example-bucket"}]}`)
	var pd PolicyDocument
	expectedErr := errors.New("error unmarshalling a statement: effect is absent or a non-string")

	err := pd.UnmarshalJSON(data)

	if !reflect.DeepEqual(expectedErr, err) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestPolicyDocument_UnmarshalJSONNoStatementBlock(t *testing.T) {
	data := []byte(`{"Version":"2012-10-17","Id":"id"}`)
	var pd PolicyDocument
	expectedErr := errors.New("Statements array is required")

	err := pd.UnmarshalJSON(data)

	if !reflect.DeepEqual(expectedErr, err) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestPolicyDocument_UnmarshalJSON1(t *testing.T) {
	data := []byte(`{"Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":["arn:aws:iam::123456789012:user/JohnDoe"]},"NotAction":"s3:ListBucket","Resource":["arn:aws:s3:::example-bucket"]}]}`)
	var pd PolicyDocument
	var expectedErr = (error)(nil)
	err := pd.UnmarshalJSON(data)

	expected := PolicyDocument{
		Statements: &[]Statement{{
			Effect:         stringOf("Allow"),
			Principal:      false,
			Action:         false,
			Resource:       true,
			PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
			ActionValue:    "s3:ListBucket",
			ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
		}},
	}
	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
	if !pd.Equals(expected) {
		t.Errorf("Expected: \n%v\n\t, got: \n%v", expected.String(), pd.String())
	}
}

func TestPolicyDocument_UnmarshalJSON2(t *testing.T) {
	data := []byte(`{"Version": "2008-10-17", "Id": "i2d", "Statement":[{"Effect":"Allow","NotPrincipal":{"AWS":["arn:aws:iam::123456789012:user/JohnDoe"]},"NotAction":"s3:ListBucket","Resource":["arn:aws:s3:::example-bucket"]}]}`)
	var pd PolicyDocument
	var expectedErr = (error)(nil)
	err := pd.UnmarshalJSON(data)

	expected := PolicyDocument{
		Statements: &[]Statement{{
			Effect:         stringOf("Allow"),
			Principal:      false,
			Action:         false,
			Resource:       true,
			PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
			ActionValue:    "s3:ListBucket",
			ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
		}},
		Version: stringToStringPtr("2008-10-17"),
		Id:      stringToStringPtr("i2d"),
	}
	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
	if !pd.Equals(expected) {
		t.Errorf("Expected: \n%v\n\t, got: \n%v", expected.String(), pd.String())
	}
}

func TestPolicyDocument_UnmarshalJSON3(t *testing.T) {
	data := []byte(`{"Version": "2012-10-17", "Id": "i2d", "Statement":[]}`)
	var pd PolicyDocument
	var expectedErr = (error)(nil)
	err := pd.UnmarshalJSON(data)

	expected := PolicyDocument{
		Statements: &[]Statement{},
		Version:    stringToStringPtr("2012-10-17"),
		Id:         stringToStringPtr("i2d"),
	}
	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
	if !pd.Equals(expected) {
		t.Errorf("Expected: \n%v\n\t, got: \n%v", expected.String(), pd.String())
	}
}

func TestPolicyDocument_UnmarshalJSONWrongVersion(t *testing.T) {
	data := []byte(`{"Version": "2012-10-18", "Id": "i2d", "Statement":[]}`)
	var pd PolicyDocument
	expectedErr := errors.New("Version must be 2012-10-17 or 2008-10-17")

	err := pd.UnmarshalJSON(data)

	if !reflect.DeepEqual(expectedErr, err) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}

}

func TestPolicyDocument_UnmarshalInvalidJSON(t *testing.T) {
	data := []byte(`invalid json`)
	var pd PolicyDocument
	expectedErr := errors.New("invalid character 'i' looking for beginning of value")

	err := pd.UnmarshalJSON(data)

	if !reflect.DeepEqual(err.Error(), expectedErr.Error()) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestPolicyDocument_UnmarshalJSONInvalidKey(t *testing.T) {
	data := []byte(`{"invalid_key": "value"}`)
	var pd PolicyDocument
	expectedErr := errors.New("unexpected key in JSON: invalid_key")
	err := pd.UnmarshalJSON(data)

	if !reflect.DeepEqual(expectedErr, err) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}
