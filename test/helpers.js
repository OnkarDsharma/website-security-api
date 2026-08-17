const assert = require('node:assert/strict');

function makeHeaders(values = {}) {
  const normalized = new Map(
    Object.entries(values).map(([key, value]) => [key.toLowerCase(), value])
  );

  return {
    get(name) {
      return normalized.get(name.toLowerCase()) || null;
    }
  };
}

function makeResponse({ status = 200, headers = {}, body = '' } = {}) {
  return {
    status,
    headers: makeHeaders(headers),
    async text() {
      return body;
    }
  };
}

function findingShapeAssert(finding) {
  assert.equal(typeof finding.category, 'string');
  assert.equal(typeof finding.check, 'string');
  assert.equal(typeof finding.status, 'string');
  assert.equal(typeof finding.severity, 'string');
  assert.equal(typeof finding.detail, 'string');
}

function createMockResponse() {
  const res = {
    statusCode: undefined,
    body: undefined,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    }
  };

  return res;
}

module.exports = {
  createMockResponse,
  findingShapeAssert,
  makeResponse
};
