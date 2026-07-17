import type { ScanAiSummary } from "./types";

export default function AiSummaryPanel({ ai }: { ai: ScanAiSummary }) {
  if (!ai?.summary) return null;
  const risk = ai.riskLevel === "clean" ? "low" : ai.riskLevel;
  return (
    <div className={`ai-analysis risk-${ai.riskLevel}`}>
      <div className="ai-analysis-head">
        <span className="ai-chip">◆ Analyst summary</span>
        <span className={`tag ${risk}`}>
          {ai.riskLevel === "clean" ? "no critical risk" : `${ai.riskLevel} risk`}
        </span>
      </div>
      <p className="ai-summary">{ai.summary}</p>
      {ai.maxCompanyDamage && (
        <div className="max-company-damage">
          <div className="max-damage-label">Maximum damage to your company</div>
          <p>{ai.maxCompanyDamage}</p>
        </div>
      )}
      {ai.attackChain && (
        <div className="attack-chain">
          <div className="max-damage-label">Likely attack chain</div>
          <p>{ai.attackChain}</p>
        </div>
      )}
    </div>
  );
}
