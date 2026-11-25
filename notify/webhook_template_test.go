package notify

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// This file pins the **capability boundary** of the generic Webhook template.
//
// It is the only place in the whole package where "a user-supplied string gets
// evaluated as code", so what it can and cannot do must be made explicit, and those
// properties nailed down with tests -- otherwise someday someone casually adds a
// method to the template context, or adds a readFile to the FuncMap, and the
// capability surface silently grows while the diff looks like nothing more than a
// harmless little function.

// TestTemplateContextHasNoMethods is the most important one.
//
// text/template calls exported methods ({{.Foo}} can both read a field and call a
// method). So as soon as the template context can reach **any** type with exported
// methods, those methods are effectively exposed to template authors. The context of
// this feature is deliberately pure data (exported fields only, zero methods).
//
// If this fails: someone has added a method to webhookTemplateData / webhookItem.
// Before deciding to let it through, think carefully about whether that method can
// be used by a template to read something that should not be exposed.
func TestTemplateContextHasNoMethods(t *testing.T) {
	for _, v := range []any{webhookTemplateData{}, webhookItem{}} {
		typ := reflect.TypeOf(v)
		if n := typ.NumMethod(); n != 0 {
			var names []string
			for i := 0; i < n; i++ {
				names = append(names, typ.Method(i).Name)
			}
			t.Fatalf("%s exposes %d method(s) (%s): text/template can call them, "+
				"which opens the capabilities of these methods to template authors", typ.Name(), n, strings.Join(names, ", "))
		}
	}
}

// TestTemplateFuncsAreMinimal pins the set of functions exposed to templates.
//
// Every extra function in the FuncMap is one more capability. Currently there are
// only json / jsons, whose job is to serialize values into JSON fragments -- they
// cannot read files, cannot send requests and cannot execute commands.
func TestTemplateFuncsAreMinimal(t *testing.T) {
	var got []string
	for name := range webhookTemplateFuncs {
		got = append(got, name)
	}
	sort.Strings(got)
	want := []string{"json", "jsons"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the template function set changed: got %v, expected %v. Before adding a function, confirm it does not widen the capability surface "+
			"(must not read or write files, must not make network requests, must not execute commands)", got, want)
	}
}

// TestTemplateCannotReachUnknownData covers out-of-bounds access in templates:
// accessing something that does not exist must fail rather than echo something
// back; and the failure message must not carry internal data out.
func TestTemplateCannotReachUnknownData(t *testing.T) {
	_, err := renderWebhookBody(`{"x": {{.Environment}}, "y": {{.Env}}}`, singleMsg())
	if err == nil {
		t.Fatal("accessing a nonexistent field should return an error")
	}
	// Real content from the template context (finding title/summary) must not appear
	// in the error.
	for _, leak := range []string{"SQL injection", "parameter id"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("the template error leaked message content %q: %v", leak, err)
		}
	}
}

// TestTemplateRenderFailsPermanently: a wrongly written template is a configuration
// error that retrying will not heal. If it were classified as retryable, one bad
// template would make every delivery run three rounds of backoff for nothing.
func TestTemplateRenderFailsPermanently(t *testing.T) {
	cfg := map[string]any{
		"url":           "https://example.com/hook",
		"body_template": `{{.Items.`,
	}
	if err := (webhookChannel{}).Validate(cfg); err == nil {
		t.Fatal("a template syntax error should be caught at save time")
	}
	// Even when validation is bypassed and delivery is attempted directly, it must
	// be a permanent failure rather than being retried over and over.
	_, err := (webhookChannel{}).Send(context.Background(), cfg, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("a bad template should be a permanent failure, got %v", err)
	}
}

// TestTemplateCanOnlyProduceJSON covers the constraint that "the template render
// result must be valid JSON". It also happens to block usages like "generating plain
// text with a template to trigger some other protocol".
func TestTemplateCanOnlyProduceJSON(t *testing.T) {
	// A valid template passes.
	ok := map[string]any{"url": "https://example.com/hook", "body_template": `{"t":{{json .Title}}}`}
	if err := (webhookChannel{}).Validate(ok); err != nil {
		t.Fatalf("a valid template should pass validation: %v", err)
	}
	// When the render result is not JSON it must be rejected (rather than sent out
	// as is).
	bad := map[string]any{"url": "http://127.0.0.1:1/hook", "body_template": `not json {{.Count}}`}
	_, err := (webhookChannel{}).Send(context.Background(), bad, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("a non-JSON render result should be a permanent failure, got %v", err)
	}
	if !strings.Contains(err.Error(), "valid JSON") {
		t.Errorf("the error message should explain that it is a JSON problem, got %v", err)
	}
}
