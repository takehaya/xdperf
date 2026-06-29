# CLAUDE.md

このファイルは、Claude Code (claude.ai/code) がこのリポジトリで作業する際のガイダンスを提供します。

**このリポジトリは基本的に日本語で回答してください。**

プロジェクト概要・ビルドコマンド・アーキテクチャ・コード規約などの本体ガイダンスは、ツール中立な [AGENTS.md](AGENTS.md) に集約しています。以下の import で取り込みます (Claude Code 以外のエージェントは AGENTS.md を直接参照してください)。

@AGENTS.md

<!-- OCR:START -->
## Open Code Review Instructions

These instructions are for AI assistants handling code review in this project.

Always open `.ocr/skills/SKILL.md` when the request:
- Asks for code review, PR review, or feedback on changes
- Mentions "review my code" or similar phrases
- Wants multi-perspective analysis of code quality
- Asks to map, organize, or navigate a large changeset

Use `.ocr/skills/SKILL.md` to learn:
- How to run the 8-phase review workflow
- How to generate a Code Review Map for large changesets
- Available reviewer personas and their focus areas
- Session management and output format

Keep this managed block so `ocr init` can refresh the instructions.
<!-- OCR:END -->
