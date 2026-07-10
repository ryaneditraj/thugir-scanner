/**
 * Lightweight blackboard — Fact/Intent tracking ported from VulnClaw solver.
 * Prevents probe loops: once a path is concluded, don't re-probe it.
 */

export type IntentStatus = "open" | "claimed" | "concluded" | "abandoned";

export interface BoardFact {
  id: string;
  text: string;
  source: string;
  at: string;
}

export interface BoardIntent {
  id: string;
  fromFactId: string;
  direction: string;
  status: IntentStatus;
  at: string;
}

export interface Blackboard {
  facts: BoardFact[];
  intents: BoardIntent[];
}

export function createBlackboard(): Blackboard {
  return { facts: [], intents: [] };
}

export function addFact(board: Blackboard, text: string, source: string): Blackboard {
  const id = `f${board.facts.length + 1}`;
  return {
    ...board,
    facts: [...board.facts, { id, text, source, at: new Date().toISOString() }]
  };
}

export function proposeIntent(board: Blackboard, fromFactId: string, direction: string): Blackboard | null {
  const open = board.intents.filter((i) => i.status === "open" || i.status === "claimed");
  if (open.length >= 8) return null;
  const dup = board.intents.some(
    (i) => i.direction === direction && i.status !== "abandoned" && i.status !== "concluded"
  );
  if (dup) return null;
  const id = `i${board.intents.length + 1}`;
  return {
    ...board,
    intents: [...board.intents, { id, fromFactId, direction, status: "open", at: new Date().toISOString() }]
  };
}

export function claimIntent(board: Blackboard): { board: Blackboard; intent: BoardIntent } | null {
  const next = board.intents.find((i) => i.status === "open");
  if (!next) return null;
  const intents = board.intents.map((i) =>
    i.id === next.id ? { ...i, status: "claimed" as IntentStatus } : i
  );
  return { board: { ...board, intents }, intent: { ...next, status: "claimed" } };
}

export function concludeIntent(board: Blackboard, intentId: string, factText: string, source: string): Blackboard {
  const intents = board.intents.map((i) =>
    i.id === intentId ? { ...i, status: "concluded" as IntentStatus } : i
  );
  return addFact({ ...board, intents }, factText, source);
}

export function blackboardSummary(board: Blackboard, maxFacts = 12): string {
  const facts = board.facts.slice(-maxFacts).map((f) => `- [${f.id}] ${f.text}`).join("\n");
  const open = board.intents.filter((i) => i.status === "open").map((i) => i.direction);
  return `Facts:\n${facts || "(none)"}\nOpen intents: ${open.join("; ") || "(none)"}`;
}
