const SEVERITY_DEDUCTIONS = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3
};

function calculateRisk(findings) {
  let score = 100;
  const summary = { critical: 0, high: 0, medium: 0, low: 0 };

  for (const finding of findings) {
    const severity = finding.severity;
    if (SEVERITY_DEDUCTIONS[severity] !== undefined) {
      score -= SEVERITY_DEDUCTIONS[severity];
      summary[severity] += 1;
    }
  }

  score = Math.max(0, score);

  let riskLevel;
  if (score >= 80) riskLevel = 'low';
  else if (score >= 50) riskLevel = 'moderate';
  else if (score >= 20) riskLevel = 'high';
  else riskLevel = 'critical';

  return { score, riskLevel, summary };
}

module.exports = { calculateRisk };
