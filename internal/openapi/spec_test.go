package openapi

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func loadPetstore(t *testing.T) *Spec {
	t.Helper()
	data, err := os.ReadFile("testdata/petstore.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return s
}

func toolsByName(t *testing.T, tools []*Tool) map[string]*Tool {
	t.Helper()
	m := map[string]*Tool{}
	for _, tl := range tools {
		m[tl.Name] = tl
	}
	return m
}

func names(tools []*Tool) []string {
	var out []string
	for _, t := range tools {
		out = append(out, t.Name)
	}
	sort.Strings(out)
	return out
}

func TestParseMetadata(t *testing.T) {
	s := loadPetstore(t)
	if s.Title != "Petstore" || s.Version != "1.2.0" {
		t.Errorf("info = %q %q", s.Title, s.Version)
	}
	if s.ServerURL != "https://eu.petstore.example.com/v1" {
		t.Errorf("server variables not expanded: %q", s.ServerURL)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"not json":     `openapi: 3.0.0`,
		"swagger 2":    `{"swagger":"2.0","paths":{}}`,
		"no version":   `{"paths":{}}`,
		"version 4":    `{"openapi":"4.0.0","paths":{"/a":{"get":{}}}}`,
		"no ops":       `{"openapi":"3.1.0","paths":{}}`,
		"bad location": `{"openapi":"3.1.0","paths":{"/a":{"get":{"parameters":[{"name":"x","in":"body"}]}}}}`,
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestBuildToolsNamesAndAnnotations(t *testing.T) {
	tools, err := loadPetstore(t).BuildTools(Filter{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"createPet", "deletePet", "getCategoryTree", "getPet", "listPets", "patch_pets_petId", "replacePets", "uploadPhoto"}
	if got := names(tools); !reflect.DeepEqual(got, want) {
		t.Fatalf("tool names = %v, want %v", got, want)
	}
	m := toolsByName(t, tools)

	if a := m["getPet"].Annotations; a["readOnlyHint"] != true || a["title"] != "Get a pet" {
		t.Errorf("getPet annotations = %v", a)
	}
	if a := m["deletePet"].Annotations; a["destructiveHint"] != true || a["readOnlyHint"] != false {
		t.Errorf("deletePet annotations = %v", a)
	}
	if d := m["getPet"].Description; !strings.Contains(d, "Returns a single pet by id.") || !strings.Contains(d, "(GET /pets/{petId})") {
		t.Errorf("getPet description = %q", d)
	}
	if d := m["replacePets"].Description; !strings.Contains(d, "Deprecated.") {
		t.Errorf("deprecated not noted: %q", d)
	}
	if m["patch_pets_petId"].Method() != "PATCH" || m["patch_pets_petId"].Path() != "/pets/{petId}" {
		t.Errorf("Method/Path wrong")
	}
}

func props(t *testing.T, tl *Tool) map[string]any {
	t.Helper()
	p, _ := tl.InputSchema["properties"].(map[string]any)
	return p
}

func required(tl *Tool) []string {
	r, _ := tl.InputSchema["required"].([]string)
	return r
}

func TestParametersBecomeArguments(t *testing.T) {
	tools, _ := loadPetstore(t).BuildTools(Filter{})
	m := toolsByName(t, tools)

	lp := props(t, m["listPets"])
	for _, want := range []string{"limit", "tags", "ids", "X-Request-Source"} {
		if _, ok := lp[want]; !ok {
			t.Errorf("listPets missing argument %q", want)
		}
	}
	// Authorization header params are ignored per the OpenAPI spec, cookie
	// params are unsupported: neither may become an argument.
	for _, banned := range []string{"Authorization", "session"} {
		if _, ok := lp[banned]; ok {
			t.Errorf("listPets must not expose %q", banned)
		}
	}

	// Path-level $ref parameter is inherited and required.
	gp := props(t, m["getPet"])
	pid, _ := gp["petId"].(map[string]any)
	if pid["description"] != "The pet's id." {
		t.Errorf("petId schema = %v", pid)
	}
	if !reflect.DeepEqual(required(m["getPet"]), []string{"petId"}) {
		t.Errorf("getPet required = %v", required(m["getPet"]))
	}
}

func TestObjectBodyIsFlattened(t *testing.T) {
	tools, _ := loadPetstore(t).BuildTools(Filter{})
	cp := toolsByName(t, tools)["createPet"]
	if cp.bodyMode != "flat" {
		t.Fatalf("createPet bodyMode = %q, want flat", cp.bodyMode)
	}
	p := props(t, cp)
	name, _ := p["name"].(map[string]any)
	if !reflect.DeepEqual(name["examples"], []any{"Rex"}) {
		t.Errorf("example not rewritten to examples: %v", name)
	}
	if _, ok := name["example"]; ok {
		t.Errorf("OpenAPI-only keyword example leaked: %v", name)
	}
	owner, _ := p["owner"].(map[string]any)
	if !reflect.DeepEqual(owner["type"], []any{"string", "null"}) {
		t.Errorf("nullable not converted: %v", owner)
	}
	if !reflect.DeepEqual(required(cp), []string{"name"}) {
		t.Errorf("createPet required = %v", required(cp))
	}
}

func TestNonObjectBodyIsBodyArgument(t *testing.T) {
	tools, _ := loadPetstore(t).BuildTools(Filter{})
	rp := toolsByName(t, tools)["replacePets"]
	if rp.bodyMode != "arg" {
		t.Fatalf("replacePets bodyMode = %q, want arg", rp.bodyMode)
	}
	body, _ := props(t, rp)["body"].(map[string]any)
	if body["type"] != "array" || body["description"] != "All pets." {
		t.Errorf("body schema = %v", body)
	}
	if !reflect.DeepEqual(required(rp), []string{"body"}) {
		t.Errorf("replacePets required = %v", required(rp))
	}
	// The allOf $refs inside items are inlined.
	if strings.Contains(mustJSON(t, rp.InputSchema), "$ref") {
		t.Errorf("unresolved $ref in %s", mustJSON(t, rp.InputSchema))
	}
}

func TestVendorKeywordsDroppedButPropertyNamesKept(t *testing.T) {
	tools, _ := loadPetstore(t).BuildTools(Filter{})
	pp := toolsByName(t, tools)["patch_pets_petId"]
	if pp.bodyMode != "flat" {
		t.Fatalf("merge-patch+json body not used: %q", pp.bodyMode)
	}
	if _, ok := props(t, pp)["x-internal"]; !ok {
		t.Errorf("a property literally named x-internal must survive")
	}
	if strings.Contains(mustJSON(t, pp.InputSchema), "x-vendor") {
		t.Errorf("x- extension keyword leaked")
	}
}

func TestRecursiveSchemaTerminates(t *testing.T) {
	tools, _ := loadPetstore(t).BuildTools(Filter{})
	cp := toolsByName(t, tools)["createPet"]
	js := mustJSON(t, cp.InputSchema) // must not hang or overflow
	if strings.Contains(js, "$ref") {
		t.Errorf("unresolved $ref: %s", js)
	}
	if len(js) > 20000 {
		t.Errorf("recursive schema expanded to %d bytes", len(js))
	}
}

func TestNonJSONBodyHasNoBodyArgument(t *testing.T) {
	tools, _ := loadPetstore(t).BuildTools(Filter{})
	up := toolsByName(t, tools)["uploadPhoto"]
	if up.bodyMode != "" || len(props(t, up)) != 0 {
		t.Errorf("multipart body should not become arguments: mode=%q props=%v", up.bodyMode, props(t, up))
	}
}

func TestFilter(t *testing.T) {
	s := loadPetstore(t)
	cases := []struct {
		name string
		f    Filter
		want []string
	}{
		{"read-only view", Filter{Methods: []string{"get"}}, []string{"getCategoryTree", "getPet", "listPets"}},
		{"include glob", Filter{IncludeOperations: []string{"get*"}}, []string{"getCategoryTree", "getPet"}},
		{"exclude", Filter{ExcludeOperations: []string{"deletePet", "upload*"}, IncludeTags: []string{"pets"}},
			[]string{"createPet", "getPet", "listPets", "patch_pets_petId"}},
		{"exclude tag", Filter{ExcludeTags: []string{"ADMIN"}},
			[]string{"createPet", "getCategoryTree", "getPet", "listPets", "patch_pets_petId", "uploadPhoto"}},
	}
	for _, c := range cases {
		tools, err := s.BuildTools(c.f)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got := names(tools); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if _, err := s.BuildTools(Filter{IncludeOperations: []string{"nope"}}); err == nil {
		t.Error("expected error when the filter leaves no tools")
	}
}

func TestToolNameSanitizingAndCollisions(t *testing.T) {
	doc := `{"openapi":"3.1.0","paths":{
	  "/a b/{x}":{"get":{"parameters":[{"name":"x","in":"path","schema":{"type":"string"}}]}},
	  "/one":{"get":{"operationId":"dup"}},
	  "/two":{"get":{"operationId":"dup"}},
	  "/long":{"get":{"operationId":"` + strings.Repeat("n", 80) + `"}}}}`
	s, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	tools, err := s.BuildTools(Filter{})
	if err != nil {
		t.Fatal(err)
	}
	got := names(tools)
	want := []string{"dup", "dup_2", "get_a_b_x", strings.Repeat("n", 64)}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("names = %v, want %v", got, want)
	}
}

func TestBodyParamNameCollision(t *testing.T) {
	doc := `{"openapi":"3.1.0","paths":{"/x":{"post":{
	  "parameters":[{"name":"body","in":"query","schema":{"type":"string"}}],
	  "requestBody":{"content":{"application/json":{"schema":{"type":"array"}}}}}}}}`
	s, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.BuildTools(Filter{}); err == nil {
		t.Error("expected an error for a parameter named body next to a request body")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
