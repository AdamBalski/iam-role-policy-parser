package iamrolepolicyparsing

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

/**
 * Statement struct represents a single statement in an IAM policy.
 *
 * If the JSON contained "Action" key or "NotAction", then ActionValue will be set to the value of the key.
 * Action is true if the key was "Action" and false if it was "NotAction".
 * If "Action" and "NotAction" were absent, the Action property is meaningless
 * Same for "Resource" and "NotResource", Resource and ResourceValue
 * and for "Principal" and "NotPrincipal", Principal and PrincipalValue
 *
 * for grammar see https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html
 */
type Statement struct {
	Sid            *string `json:"Sid"`
	PrincipalValue interface{}
	Principal      bool
	ActionValue    interface{}
	Action         bool
	ResourceValue  interface{}
	Resource       bool
	Effect         *string     `json:"Effect"`
	ConditionMap   interface{} `json:"Condition"`
}

func (this *Statement) String() string {
	stringPtrToString := func(ptr *string) string {
		if ptr == nil {
			return "nil"
		}
		return *ptr
	}
	return fmt.Sprintf(
		"Statement{Sid: %v, PrincipalValue: %v, Principal: %v, ActionValue: %v, Action: %v, ResourceValue: %v, Resource: %v, Effect: %v, ConditionMap: %v}",
		stringPtrToString(this.Sid),
		this.PrincipalValue,
		this.Principal,
		this.ActionValue,
		this.Action,
		this.ResourceValue,
		this.Resource,
		stringPtrToString(this.Effect),
		this.ConditionMap,
	)
}

func (this *Statement) Equals(other interface{}) bool {
	if that, ok := other.(Statement); ok {
		return !(!reflect.DeepEqual(this.ActionValue, that.ActionValue) ||
			!reflect.DeepEqual(this.ResourceValue, that.ResourceValue) ||
			!reflect.DeepEqual(this.ConditionMap, that.ConditionMap) ||
			this.Sid != nil && *this.Sid != *that.Sid ||
			this.Effect != nil && *this.Effect != *that.Effect ||
			this.ResourceValue != nil && this.Resource != that.Resource ||
			this.ActionValue != nil && this.Action != that.Action ||
			this.PrincipalValue != nil && this.Principal != that.Principal)
	}
	return false

}

func parseSid(statMap map[string]interface{}, stat *Statement) error {
	if statMap["Sid"] != nil {
		if sid, ok := statMap["Sid"].(string); !ok {
			return errors.New("sid is a non-string")
		} else {
			stat.Sid = &sid
		}
	}
	return nil
}

func parseEffect(statMap map[string]interface{}, stat *Statement) error {
	if effect, ok := statMap["Effect"].(string); !ok {
		return errors.New("effect is absent or a non-string")
	} else {
		if effect != "Allow" && effect != "Deny" {
			return errors.New(`effect should be either "Allow" or "Deny"`)
		}
		stat.Effect = &effect
	}
	return nil
}

func parsePrincipal(statMap map[string]interface{}, stat *Statement) error {
	if statMap["Principal"] != nil {
		stat.PrincipalValue = statMap["Principal"]
		stat.Principal = true
	}
	if statMap["NotPrincipal"] != nil {
		if stat.PrincipalValue != nil {
			return errors.New("principal and not-principal value shouldn't exist within a single statement block")
		}
		stat.PrincipalValue = statMap["NotPrincipal"]
		stat.Principal = false
	}
	if principalString, ok := stat.PrincipalValue.(string); ok {
		if principalString != "*" {
			return errors.New("principal value should be '*' or a map")
		}
	} else if principalMap, ok := stat.PrincipalValue.(map[string]interface{}); ok {
		for key, value := range principalMap {
			if key != "AWS" && key != "Federated" && key != "Service" && key != "CanonicalUser" {
				return errors.New(`key in principal map should be one of the following: "AWS", "Federated", "Service", "CanonicalUser"`)
			}
			if array, ok := value.([]interface{}); ok {
				for _, principalIdString := range array {
					if _, ok := principalIdString.(string); !ok {
						return errors.New("value in principal map should be a []string")
					}
				}
			} else {
				return errors.New("value in principal map should be an array")
			}
		}
	} else if stat.PrincipalValue != nil {
		return errors.New("principal value should be '*' or a map")
	}
	return nil
}

func parseAction(statMap map[string]interface{}, stat *Statement) error {
	if statMap["Action"] != nil {
		stat.ActionValue = statMap["Action"]
		stat.Action = true
	}
	if statMap["NotAction"] != nil {
		if stat.ActionValue != nil {
			return errors.New("action and not-action shouldn't exist within a single statement block")
		}
		stat.ActionValue = statMap["NotAction"]
		stat.Action = false
	}
	if stat.ActionValue == nil {
		return errors.New("action or not-action has to exist in a statement block")
	}
	switch stat.ActionValue.(type) {
	case string:
	case []interface{}:
		for _, action := range stat.ActionValue.([]interface{}) {
			if _, ok := action.(string); !ok {
				return errors.New("action value should be a []string")
			}
		}
	default:
		return errors.New("action value should either be a string or a []string")
	}
	return nil
}

func parseResource(statMap map[string]interface{}, stat *Statement) error {
	if statMap["Resource"] != nil {
		stat.ResourceValue = statMap["Resource"]
		stat.Resource = true
	}
	if statMap["NotResource"] != nil {
		if stat.ResourceValue != nil {
			return errors.New("resource and not-resource shouldn't exist within a single statement block")
		}
		stat.ResourceValue = statMap["NotResource"]
		stat.Resource = false
	}
	if stat.ResourceValue == nil {
		return errors.New("resource or not-resource has to exist in a statement block")
	}
	switch stat.ResourceValue.(type) {
	case string:
	case []interface{}:
		for _, resource := range stat.ResourceValue.([]interface{}) {
			if _, ok := resource.(string); !ok {
				return errors.New("resource value should be a []string")
			}
		}
	default:
		return errors.New("resource value should either be a string or a []string")
	}
	return nil
}

func parseCondition(statMap map[string]interface{}, stat *Statement) {
	stat.ConditionMap = statMap["Condition"]
}

// UnmarshalJSON function

func (stat *Statement) UnmarshalJSON(data []byte) error {
	// reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html

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
		if key != "Sid" &&
			key != "Principal" &&
			key != "Action" &&
			key != "Resource" &&
			key != "NotAction" &&
			key != "Effect" &&
			key != "Condition" &&
			key != "NotResource" &&
			key != "NotPrincipal" {
			return errors.New(fmt.Sprintf("unknown key: %s", key))
		}
	}

	if err := parseSid(statMap, stat); err != nil {
		return err
	}
	if err := parseEffect(statMap, stat); err != nil {
		return err
	}
	if err := parsePrincipal(statMap, stat); err != nil {
		return err
	}
	if err := parseAction(statMap, stat); err != nil {
		return err
	}
	if err := parseResource(statMap, stat); err != nil {
		return err
	}
	parseCondition(statMap, stat)

	return nil
}

func (stat Statement) isResourceAWildcard() bool {
	// if NotResource was present instead of Resource
	if !stat.Resource {
		return false
	}

	if stat.Resource {
		if resourceString, ok := stat.ResourceValue.(string); ok {
			return resourceString == "*"
		}
	}
	return false
}
