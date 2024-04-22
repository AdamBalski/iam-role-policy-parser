package iamrolepolicyparsing

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func stringOf(s string) *string {
	return &s
}

func TestStatement_String(t *testing.T) {
	stat := Statement{
		Sid:            stringOf("123"),
		Effect:         stringOf("Allow"),
		Principal:      true,
		Action:         true,
		Resource:       true,
		PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
		ActionValue:    []interface{}{"s3:ListBucket"},
		ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
	}
	expected := "Statement{Sid: 123, PrincipalValue: map[AWS:[arn:aws:iam::123456789012:user/JohnDoe]], Principal: true, ActionValue: [s3:ListBucket], Action: true, ResourceValue: [arn:aws:s3:::example-bucket], Resource: true, Effect: Allow, ConditionMap: <nil>}"
	if stat.String() != expected {
		t.Errorf("Expected: \n%v\n\t, got: \n%v", expected, stat.String())
	}
}

func TestStatement_EqualsIfNotEqual(t *testing.T) {
	stat1 := Statement{
		Sid:            stringOf("123"),
		Effect:         stringOf("Allow"),
		Principal:      true,
		Action:         true,
		Resource:       true,
		PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
		ActionValue:    []interface{}{"s3:ListBucket"},
		ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
	}
	stat2 := Statement{
		Sid:            stringOf("123"),
		Effect:         stringOf("Allow"),
		Principal:      false,
		Action:         true,
		Resource:       true,
		PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
		ActionValue:    []interface{}{"s3:ListBucket"},
		ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
	}
	if stat1.Equals(stat2) {
		t.Errorf("Expected: not equal, got: equal")
	}
}

func TestStatement_EqualsIfEqual(t *testing.T) {
	stat1 := Statement{
		Sid:            stringOf("123"),
		Effect:         stringOf("Allow"),
		Principal:      true,
		Action:         true,
		Resource:       true,
		PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
		ActionValue:    []interface{}{"s3:ListBucket"},
		ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
	}
	stat2 := Statement{
		Sid:            stringOf("123"),
		Effect:         stringOf("Allow"),
		Principal:      true,
		Action:         true,
		Resource:       true,
		PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
		ActionValue:    []interface{}{"s3:ListBucket"},
		ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
	}
	if !stat1.Equals(stat2) {
		t.Errorf("Expected: equal, got: not equal")
	}
}

func TestStatement_EqualsIfNil(t *testing.T) {
	stat1 := Statement{
		Sid:            stringOf("123"),
		Effect:         stringOf("Allow"),
		Principal:      true,
		Action:         true,
		Resource:       true,
		PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
		ActionValue:    []interface{}{"s3:ListBucket"},
		ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
	}
	if stat1.Equals(nil) {
		t.Errorf("Expected: not equal, got: equal")
	}
}

func TestStatement_EqualsIfNotAStatement(t *testing.T) {
	stat1 := Statement{
		Sid:            stringOf("123"),
		Effect:         stringOf("Allow"),
		Principal:      true,
		Action:         true,
		Resource:       true,
		PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
		ActionValue:    []interface{}{"s3:ListBucket"},
		ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
	}
	var stat2 interface{} = "Not a Statement"
	if stat1.Equals(stat2) {
		t.Errorf("Expected: false, got: true")
	}
}

func TestStatement_UnmarshalValid1(t *testing.T) {
	data := []byte(`{"Sid":"123","Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:user/JohnDoe"]},"Action":["s3:ListBucket"],"NotResource":"arn:aws:s3:::example-bucket"}`)
	var stat Statement
	var expectedErr = (error)(nil)
	err := stat.UnmarshalJSON(data)

	expected := Statement{
		Sid:            stringOf("123"),
		Effect:         stringOf("Allow"),
		Principal:      true,
		Action:         true,
		Resource:       false,
		PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
		ActionValue:    []interface{}{"s3:ListBucket"},
		ResourceValue:  "arn:aws:s3:::example-bucket",
	}
	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
	if !stat.Equals(expected) {
		t.Errorf("Expected: \n%v\n\t, got: \n%v", expected.String(), stat.String())
	}
}

func TestStatement_UnmarshalValid2(t *testing.T) {
	data := []byte(`{"Effect":"Allow","NotPrincipal":{"AWS":["arn:aws:iam::123456789012:user/JohnDoe"]},"NotAction":"s3:ListBucket","Resource":["arn:aws:s3:::example-bucket"]}`)
	var stat Statement
	var expectedErr = (error)(nil)
	err := stat.UnmarshalJSON(data)

	expected := Statement{
		Effect:         stringOf("Allow"),
		Principal:      false,
		Action:         false,
		Resource:       true,
		PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
		ActionValue:    "s3:ListBucket",
		ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
	}
	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
	if !stat.Equals(expected) {
		t.Errorf("Expected: \n%v\n\t, got: \n%v", expected.String(), stat.String())
	}
}

func TestStatement_UnmarshalValid3(t *testing.T) {
	data := []byte(`{"Effect":"Allow","NotAction":"s3:ListBucket","Resource":["arn:aws:s3:::example-bucket"]}`)
	var stat Statement
	var expectedErr = (error)(nil)
	err := stat.UnmarshalJSON(data)

	expected := Statement{
		Sid:            nil,
		Effect:         stringOf("Allow"),
		Principal:      true,
		Action:         false,
		Resource:       true,
		PrincipalValue: nil,
		ActionValue:    "s3:ListBucket",
		ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
	}
	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
	if !stat.Equals(expected) {
		t.Errorf("Expected: \n%v\n\t, got: \n%v", expected.String(), stat.String())
	}
}

func TestStatement_UnmarshalInvalidJSON(t *testing.T) {
	data := []byte(`invalid json`)
	var stat Statement
	expectedErr := errors.New("invalid character 'i' looking for beginning of value")

	err := stat.UnmarshalJSON(data)

	if !reflect.DeepEqual(err.Error(), expectedErr.Error()) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestStatement_UnmarshalUnwantedProperty(t *testing.T) {
	data := []byte(`{"Sid":"123","Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:user/JohnDoe"]},"Action":"s3:ListBucket","Resource":"arn:aws:s3:::example-bucket","Unwanted":"property"}`)
	var stat Statement
	expectedErr := errors.New("unknown key: Unwanted")

	err := stat.UnmarshalJSON(data)

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestStatement_UnmarshalMissingEffect(t *testing.T) {
	data := []byte(`{"Sid":"123","Principal":{"AWS":["arn:aws:iam::123456789012:user/JohnDoe"]},"Action":"s3:ListBucket","Resource":"arn:aws:s3:::example-bucket"}`)
	var stat Statement
	expectedErr := errors.New("effect is absent or a non-string")

	err := stat.UnmarshalJSON(data)

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestStatement_UnmarshalNonStringEffect(t *testing.T) {
	data := []byte(`{"Sid":"123","Effect":123,"Principal":{"AWS":["arn:aws:iam::123456789012:user/JohnDoe"]},"Action":"s3:ListBucket","Resource":"arn:aws:s3:::example-bucket"}`)
	var stat Statement
	expectedErr := errors.New("effect is absent or a non-string")

	err := stat.UnmarshalJSON(data)

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestStatement_UnmarshalInvalidEffect(t *testing.T) {
	data := []byte(`{"Sid":"123","Effect":"Invalid","Principal":{"AWS":["arn:aws:iam::123456789012:user/JohnDoe"]},"Action":"s3:ListBucket","Resource":"arn:aws:s3:::example-bucket"}`)
	var stat Statement
	expectedErr := errors.New(`effect should be either "Allow" or "Deny"`)

	err := stat.UnmarshalJSON(data)

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestStatement_UnmarshalInvalidSidType(t *testing.T) {
	data := []byte(`{"Sid":123,"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:user/JohnDoe"]},"Action":"s3:ListBucket","Resource":"arn:aws:s3:::example-bucket"}`)
	var stat Statement
	expectedErr := errors.New("sid is a non-string")

	err := stat.UnmarshalJSON(data)

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestStatement_UnmarshalInvalidActionType(t *testing.T) {
	data := []byte(`{"Sid":"123","Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:user/JohnDoe"]},"Action":123,"Resource":"arn:aws:s3:::example-bucket"}`)
	var stat Statement
	expectedErr := errors.New("action value should either be a string or a []string")

	err := stat.UnmarshalJSON(data)

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestStatement_UnmarshalPrincipalAndNotPrincipalExist(t *testing.T) {
	data := []byte(`{"Sid":"123","Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:user/JohnDoe"]},"NotPrincipal":{"AWS":["arn:aws:iam::123456789012:user/JaneDoe"]},"Action":"s3:ListBucket","Resource":"arn:aws:s3:::example-bucket"}`)
	var stat Statement
	expectedErr := errors.New("principal and not-principal value shouldn't exist within a single statement block")

	err := stat.UnmarshalJSON(data)

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestStatement_UnmarshalActionAndNotActionExist(t *testing.T) {
	data := []byte(`{"Sid":"123","Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:user/JohnDoe"]},"Action":["s3:ListBucket"],"NotAction":["s3:GetObject"],"Resource":"arn:aws:s3:::example-bucket"}`)
	var stat Statement
	expectedErr := errors.New("action and not-action shouldn't exist within a single statement block")

	err := stat.UnmarshalJSON(data)

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestStatement_UnmarshalResourceAndNotResourceExist(t *testing.T) {
	data := []byte(`{"Sid":"123","Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:user/JohnDoe"]},"Action":"s3:ListBucket","Resource":"arn:aws:s3:::example-bucket","NotResource":"arn:aws:s3:::example-bucket"}`)
	var stat Statement
	expectedErr := errors.New("resource and not-resource shouldn't exist within a single statement block")

	err := stat.UnmarshalJSON(data)

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestStatement_UnmarshalInvalidResourceType(t *testing.T) {
	data := []byte(`{"Sid":"123","Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:user/JohnDoe"]},"Action":"s3:ListBucket","Resource":123}`)
	var stat Statement
	expectedErr := errors.New("resource value should either be a string or a []string")

	err := stat.UnmarshalJSON(data)

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestStatement_UnmarshalPrincipalValueIsNonAsteriskString(t *testing.T) {
	data := []byte(`{"Sid":"123","Effect":"Allow","Principal":"lol","Action":"s3:ListBucket","Resource":"arn:aws:s3:::example-bucket"}`)
	var stat Statement
	expectedErr := errors.New("principal value should be '*' or a map")

	err := stat.UnmarshalJSON(data)

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestStatement_UnmarshalPrincipalValueIsOfInvalidType(t *testing.T) {
	data := []byte(`{"Sid":"123","Effect":"Allow","Principal":123,"Action":"s3:ListBucket","Resource":"arn:aws:s3:::example-bucket"}`)
	var stat Statement
	expectedErr := errors.New("principal value should be '*' or a map")

	err := stat.UnmarshalJSON(data)

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestStatement_UnmarshalPrincipalMapValueIsNotAStringSlice(t *testing.T) {
	data := []byte(`{"Sid":"123","Effect":"Allow","Principal":{"AWS":[1,"arn:aws:iam::123456789012:user/JohnDoe"]},"Action":"s3:ListBucket","Resource":"arn:aws:s3:::example-bucket"}`)
	var stat Statement
	expectedErr := errors.New("value in principal map should be a []string")

	err := stat.UnmarshalJSON(data)

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestStatement_UnmarshalPrincipalMapValueIsNotASlice(t *testing.T) {
	data := []byte(`{"Sid":"123","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/JohnDoe"},"Action":"s3:ListBucket","Resource":"arn:aws:s3:::example-bucket"}`)
	var stat Statement
	expectedErr := errors.New("value in principal map should be an array")

	err := stat.UnmarshalJSON(data)

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestStatement_UnmarshalPrincipalMapKeyIsNotValid(t *testing.T) {
	data := []byte(`{"Sid":"123","Effect":"Allow","Principal":{"Invalid":["arn:aws:iam::123456789012:user/JohnDoe"]},"Action":"s3:ListBucket","Resource":"arn:aws:s3:::example-bucket"}`)
	var stat Statement
	expectedErr := errors.New(`key in principal map should be one of the following: "AWS", "Federated", "Service", "CanonicalUser"`)

	err := stat.UnmarshalJSON(data)

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestStatement_UnmarshalActionOrAndNotActionNotExisting(t *testing.T) {
	data := []byte(`{"Sid":"123","Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:user/JohnDoe"]},"Resource":"arn:aws:s3:::example-bucket"}`)
	var stat Statement
	expectedErr := errors.New("action or not-action has to exist in a statement block")

	err := stat.UnmarshalJSON(data)

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestStatement_UnmarshalMissingResourceOrNotResource(t *testing.T) {
	data := []byte(`{"Sid":"123","Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:user/JohnDoe"]},"Action":"s3:ListBucket"}`)
	var stat Statement
	expectedErr := errors.New("resource or not-resource has to exist in a statement block")

	err := stat.UnmarshalJSON(data)

	if !reflect.DeepEqual(err, expectedErr) {
		t.Errorf("Expected error: %v, got: %v", expectedErr, err)
	}
}

func TestStatement_UnmarshalWhenNull(t *testing.T) {
	stat := Statement{
		Sid:            stringOf("123"),
		Effect:         stringOf("Allow"),
		Principal:      true,
		Action:         true,
		Resource:       true,
		PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
		ActionValue:    []interface{}{"s3:ListBucket"},
		ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
	}
	original := Statement{
		Sid:            stringOf("123"),
		Effect:         stringOf("Allow"),
		Principal:      true,
		Action:         true,
		Resource:       true,
		PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
		ActionValue:    []interface{}{"s3:ListBucket"},
		ResourceValue:  []interface{}{"arn:aws:s3:::example-bucket"},
	}
	data := `null`
	err := json.Unmarshal([]byte(data), &stat)

	if !stat.Equals(original) {
		t.Errorf("Expected Unmarshalling to be a noop")
	}
	if err != nil {
		t.Errorf(`Expected Unmarshalling a "null" to be not throw an error`)
	}
}

func TestStatement_IsResourceAWildcardIfTrue(t *testing.T) {
	stat := Statement{
		Sid:            stringOf("123"),
		Effect:         stringOf("Allow"),
		Principal:      true,
		Action:         true,
		Resource:       true,
		PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
		ActionValue:    []interface{}{"s3:ListBucket"},
		ResourceValue:  interface{}("*"),
	}
	if !stat.isResourceAWildcard() {
		t.Errorf("Expected: true, got: false")
	}
}

func TestStatement_IsResourceAWildcardIfItsAnArray(t *testing.T) {
	stat := Statement{
		Sid:            stringOf("123"),
		Effect:         stringOf("Allow"),
		Principal:      true,
		Action:         true,
		Resource:       true,
		PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
		ActionValue:    []interface{}{"s3:ListBucket"},
		ResourceValue:  []interface{}{"*"},
	}
	if stat.isResourceAWildcard() {
		t.Errorf("Expected: false, got: true")
	}
}

func TestStatement_IsResourceAWildcardIfNot(t *testing.T) {
	stat := Statement{
		Sid:            stringOf("123"),
		Effect:         stringOf("Allow"),
		Principal:      true,
		Action:         true,
		Resource:       true,
		PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
		ActionValue:    []interface{}{"s3:ListBucket"},
		ResourceValue:  interface{}("lol"),
	}
	if stat.isResourceAWildcard() {
		t.Errorf("Expected: false, got: true")
	}
}

func TestStatement_IsResourceAWildcardIfDoesNotExist(t *testing.T) {
	stat := Statement{
		Sid:            stringOf("123"),
		Effect:         stringOf("Allow"),
		Principal:      true,
		Action:         true,
		Resource:       false,
		PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
		ActionValue:    []interface{}{"s3:ListBucket"},
	}
	if stat.isResourceAWildcard() {
		t.Errorf("Expected: false, got: true")
	}
}

func TestStatement_IsResourceAWildcardIfNotResourceExists(t *testing.T) {
	stat := Statement{
		Sid:            stringOf("123"),
		Effect:         stringOf("Allow"),
		Principal:      true,
		Action:         true,
		Resource:       false,
		PrincipalValue: map[string]interface{}{"AWS": []string{"arn:aws:iam::123456789012:user/JohnDoe"}},
		ActionValue:    []interface{}{"s3:ListBucket"},
		ResourceValue:  []interface{}{"*"},
	}
	if stat.isResourceAWildcard() {
		t.Errorf("Expected: false, got: true")
	}
}
