const assert = require('node:assert/strict');
const test = require('node:test');

const { calculateRisk } = require('../lib/scoring');

test('calculateRisk subtracts fixed severity points and summarizes findings', () => {
  const result = calculateRisk([
    { severity: 'critical' },
    { severity: 'high' },
    { severity: 'medium' },
    { severity: 'low' },
    { severity: 'info' }
  ]);

  assert.deepEqual(result, {
    score: 49,
    riskLevel: 'high',
    summary: {
      critical: 1,
      high: 1,
      medium: 1,
      low: 1
    }
  });
});

test('calculateRisk floors score at zero', () => {
  const findings = Array.from({ length: 10 }, () => ({ severity: 'critical' }));

  const result = calculateRisk(findings);

  assert.equal(result.score, 0);
  assert.equal(result.riskLevel, 'critical');
});
