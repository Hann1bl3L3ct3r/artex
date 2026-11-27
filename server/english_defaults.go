package server

import (
	"encoding/json"
	"log"
	"unicode"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
	actool "github.com/Autumn-27/norma/tool"
)

// Trigger message that the Chinese-language builds seeded for the reporter agent
// (0.3.9 up to the English translation). It is compared byte-for-byte against
// persisted rows, so it has to stay in its original Chinese.
const reporterToolCallMessageZH = "上面刚有一个漏洞被 report_finding 登记。请读取返回 JSON 的 finding_id（独立漏洞记录 ID）与 finding_node_id（探索节点 ID），" +
	"先用 get_finding_traffic(finding_id) 读取当前证据清单及其 version（空清单是正常情况，照常写报告）；" +
	"若运行指引启用自动绑定，在读取前先核实并关联本次漏洞的流量。节点详情使用 finding_node_id。" +
	"最后调用 update_finding_report(finding_id=finding_node_id, report, evidence_version=实际读取版本) 保存，" +
	"evidence_version 必须传，否则报告会被永久标记为待更新。不要混用两种编号。"

// containsHan reports whether s holds any CJK ideograph. The migration below uses it
// to tell text still left over from a Chinese-language build apart from text the user
// already wrote in English.
func containsHan(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

// localizeSeededDefaults switches the defaults that an older, Chinese-language build
// persisted in an existing database over to the English code defaults. Every seed is
// first-insert-only, so translating the code alone never reaches an upgraded
// database: its agents would keep running on the stored Chinese prompts and tool
// descriptions and keep answering in Chinese.
//
// Only text that still contains Chinese is replaced, so anything the user already
// rewrote in English survives. Prompts are appended as a new version (the previous
// one stays in the version history); tool rows keep their agent bindings and enabled
// flag. A fresh database is seeded in English and matches nothing. One-shot, guarded
// by a settings flag that is only set once every step succeeded.
func (s *Server) localizeSeededDefaults() {
	const flag = "seeded_defaults_english_v1"
	pg := s.m.pg
	if v, _, _ := pg.GetSetting(flag); v == "true" {
		return
	}
	ok := true
	fail := func(what string, err error) {
		ok = false
		log.Printf("[i18n] %s failed: %v", what, err)
	}

	// 1. Agent prompts.
	prompts := agent.BuiltinPromptSeeds()
	prompts["reporter"] = agent.ReporterDefaultPrompt
	prompts[db.FindingRetestAgentKey] = agent.RetesterDefaultPrompt
	for key, tmpl := range prompts {
		a, err := pg.GetAgentByKey(key)
		if err != nil {
			fail("load agent "+key, err)
			continue
		}
		if a == nil {
			continue
		}
		cur, err := pg.CurrentPrompt(a.ID)
		if err != nil {
			fail("read prompt of "+key, err)
			continue
		}
		if cur == tmpl || !containsHan(cur) {
			continue
		}
		if _, err := pg.ResetPromptToDefault(a.ID, tmpl); err != nil {
			fail("reset prompt of "+key, err)
			continue
		}
		log.Printf("[i18n] appended the English default prompt for agent %s (the previous version stays in its history)", key)
	}

	// 2. Built-in tool descriptions and schemas.
	type toolDefault struct {
		desc   string
		schema json.RawMessage
	}
	defaults := map[string]toolDefault{}
	for _, sd := range agent.BuiltinToolSeeds() {
		schema, _ := json.Marshal(sd.Schema)
		defaults[sd.Key] = toolDefault{sd.Desc, schema}
	}
	var coreTools []actool.CoreTool
	coreTools = append(coreTools, traffic.SeedToolMetas()...)
	coreTools = append(coreTools, s.orchestrationTools()...)
	coreTools = append(coreTools, s.platformTools()...)
	coreTools = append(coreTools, s.findingRetestTools()...)
	for _, t := range coreTools {
		schema, _ := json.Marshal(t.InputSchema())
		defaults[t.Name()] = toolDefault{t.Description(), schema}
	}
	tools, err := pg.ListTools()
	if err != nil {
		fail("list tools", err)
	}
	refreshed := 0
	for _, row := range tools {
		if !row.System || (!containsHan(row.Description) && !containsHan(string(row.Schema))) {
			continue
		}
		def, known := defaults[row.Key]
		if !known {
			log.Printf("[i18n] tool %s still has a Chinese description but no code default; left as is", row.Key)
			continue
		}
		if err := pg.RefreshToolDefaults(row.Key, def.desc, def.schema); err != nil {
			fail("refresh tool "+row.Key, err)
			continue
		}
		refreshed++
	}
	if refreshed > 0 {
		log.Printf("[i18n] refreshed %d built-in tool descriptions to the English code defaults", refreshed)
	}

	// 3. The reporter's finding trigger, when it is still the seeded Chinese text.
	triggers, err := pg.ListTriggersFor("reporter")
	if err != nil {
		fail("list reporter triggers", err)
	}
	for _, t := range triggers {
		if !t.OnToolCall || t.ToolCallMessage != reporterToolCallMessageZH {
			continue // edited by the user, or not the seeded finding trigger
		}
		t.ToolCallMessage = reporterToolCallMessage
		if err := pg.UpdateTrigger(t); err != nil {
			fail("update reporter trigger", err)
		}
	}

	// 4. Display name and description of the two seeded (non-builtin) agents. Built-in
	//    agents are upserted on every start and need nothing here.
	for key, meta := range map[string][2]string{
		"reporter":               {reporterAgentName, reporterAgentDescription},
		db.FindingRetestAgentKey: {retesterAgentName, retesterAgentDescription},
	} {
		a, err := pg.GetAgentByKey(key)
		if err != nil {
			fail("load agent "+key, err)
			continue
		}
		if a == nil || a.Builtin {
			continue
		}
		name, desc := a.Name, a.Description
		if containsHan(name) {
			name = meta[0]
		}
		if containsHan(desc) {
			desc = meta[1]
		}
		if name == a.Name && desc == a.Description {
			continue
		}
		if err := pg.UpdateAgentMeta(key, name, desc); err != nil {
			fail("rename agent "+key, err)
		}
	}

	// 5. Seeded intercept / asset-intercept rule names and deny messages.
	if err := pg.LocalizeBuiltinRules(); err != nil {
		fail("localize built-in rules", err)
	}

	if ok {
		_ = pg.SetSetting(flag, "true")
	}
}
