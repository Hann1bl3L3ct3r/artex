package server

import (
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// A database seeded by a Chinese-language build must come out in English after one
// start, while text the operator already rewrote in English is left alone.
func TestLocalizeSeededDefaults(t *testing.T) {
	s, _ := newRetestServer(t)
	pg := s.m.pg
	const flag = "seeded_defaults_english_v1"
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pg.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}

	seeds := agent.BuiltinToolSeeds()
	legacyTool, editedTool := seeds[0], seeds[1]
	legacySchema, _ := json.Marshal(legacyTool.Schema)
	editedSchema, _ := json.Marshal(editedTool.Schema)
	if err := pg.UpsertToolForce(legacyTool.Key, "旧的中文工具描述", legacySchema, json.RawMessage(`["worker"]`)); err != nil {
		t.Fatal(err)
	}
	if err := pg.UpsertToolForce(editedTool.Key, "operator-edited description", editedSchema, nil); err != nil {
		t.Fatal(err)
	}
	planner, err := pg.GetAgentByKey("planner")
	if err != nil || planner == nil {
		t.Fatalf("planner agent: %+v %v", planner, err)
	}
	worker, err := pg.GetAgentByKey("worker")
	if err != nil || worker == nil {
		t.Fatalf("worker agent: %+v %v", worker, err)
	}
	if _, err := pg.SavePrompt(planner.ID, "你是规划者。", "legacy", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.SavePrompt(worker.ID, "Operator-written worker prompt.", "custom", "test"); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE intercept_rules SET name='[内置] 删除类接口路径', message='禁止调用删除类接口' WHERE name='[Built-in] Delete endpoint paths'`)
	exec(`UPDATE asset_intercept_rules SET note='[内置] 政府网站 (.gov)' WHERE pattern='.gov' AND builtin`)
	exec(`UPDATE agents SET name='漏洞复测' WHERE key=$1`, db.FindingRetestAgentKey)
	exec(`DELETE FROM settings WHERE key=$1`, flag)
	t.Cleanup(func() {
		agents, _ := json.Marshal(legacyTool.Agents)
		_ = pg.UpsertToolForce(legacyTool.Key, legacyTool.Desc, legacySchema, agents)
		agents, _ = json.Marshal(editedTool.Agents)
		_ = pg.UpsertToolForce(editedTool.Key, editedTool.Desc, editedSchema, agents)
		_, _ = pg.ResetPromptToDefault(worker.ID, agent.BuiltinPromptSeeds()["worker"])
	})

	s.localizeSeededDefaults()

	if v, _, _ := pg.GetSetting(flag); v != "true" {
		t.Fatalf("flag not set: %q", v)
	}
	tool, err := pg.GetTool(legacyTool.Key)
	if err != nil || tool == nil || tool.Description != legacyTool.Desc || len(tool.Agents) != 1 || tool.Agents[0] != "worker" {
		t.Fatalf("legacy tool not refreshed, or its binding was lost: %+v %v", tool, err)
	}
	if tool, err = pg.GetTool(editedTool.Key); err != nil || tool == nil || tool.Description != "operator-edited description" {
		t.Fatalf("English-edited tool was overwritten: %+v %v", tool, err)
	}
	if cur, err := pg.CurrentPrompt(planner.ID); err != nil || cur != agent.BuiltinPromptSeeds()["planner"] {
		t.Fatalf("planner prompt not switched to the English default: %v", err)
	}
	if cur, err := pg.CurrentPrompt(worker.ID); err != nil || cur != "Operator-written worker prompt." {
		t.Fatalf("English custom prompt was replaced: %q %v", cur, err)
	}
	versions, err := pg.ListPromptVersions(planner.ID)
	if err != nil {
		t.Fatal(err)
	}
	kept := false
	for _, v := range versions {
		kept = kept || v.Template == "你是规划者。"
	}
	if !kept {
		t.Fatal("previous prompt version missing from the history")
	}
	var legacyRules, legacyNotes int
	if err := pg.QueryRow(`SELECT count(*) FROM intercept_rules WHERE name ~ $1 OR message ~ $1`, "[一-鿿]").Scan(&legacyRules); err != nil {
		t.Fatal(err)
	}
	if err := pg.QueryRow(`SELECT count(*) FROM asset_intercept_rules WHERE note ~ $1`, "[一-鿿]").Scan(&legacyNotes); err != nil {
		t.Fatal(err)
	}
	if legacyRules != 0 || legacyNotes != 0 {
		t.Fatalf("seeded rules still Chinese: rules=%d notes=%d", legacyRules, legacyNotes)
	}
	if a, err := pg.GetAgentByKey(db.FindingRetestAgentKey); err != nil || a == nil || a.Name != retesterAgentName {
		t.Fatalf("retester agent not renamed: %+v %v", a, err)
	}

	// One-shot: a second start appends nothing.
	s.localizeSeededDefaults()
	again, err := pg.ListPromptVersions(planner.ID)
	if err != nil || len(again) != len(versions) {
		t.Fatalf("second run appended prompt versions: %d -> %d (%v)", len(versions), len(again), err)
	}
}
