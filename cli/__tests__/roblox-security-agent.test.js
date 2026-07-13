/**
 * Ship Safe — RobloxSecurityAgent
 * ================================
 *
 * Tests Luau source detection, .rbxmx embedded-script + attribute-payload
 * decoding, the ClickFix lure, and benign-code quiet behavior.
 *
 * Run: npm test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import os from 'os';

import { RobloxSecurityAgent } from '../agents/roblox-security-agent.js';

function writeTempFile(content, ext = '.lua') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shipsafe-roblox-'));
  const file = path.join(dir, `test${ext}`);
  fs.writeFileSync(file, content);
  return { dir, file };
}

function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* */ }
}

async function scan(content, ext) {
  const { dir, file } = writeTempFile(content, ext);
  try {
    const agent = new RobloxSecurityAgent();
    const findings = await agent.analyze({ rootPath: dir, files: [file], recon: {}, options: {} });
    return findings;
  } finally { cleanup(dir); }
}

describe('RobloxSecurityAgent — Luau source', () => {
  it('flags runtime asset injection via GetObjects(rbxassetid://)', async () => {
    const f = await scan("local a = game:GetObjects('rbxassetid://114706280708394')[1]", '.lua');
    assert.ok(f.some(x => x.rule === 'ROBLOX_RUNTIME_ASSET_FETCH' && x.severity === 'critical'));
  });

  it('flags require() by numeric asset id', async () => {
    const f = await scan('local m = require(114706280708394)', '.luau');
    assert.ok(f.some(x => x.rule === 'ROBLOX_REQUIRE_BY_ASSET_ID'));
  });

  it('flags HttpService being enabled from a script', async () => {
    const f = await scan('game.HttpService.HttpEnabled = true', '.lua');
    assert.ok(f.some(x => x.rule === 'ROBLOX_HTTP_ENABLE'));
  });

  it('flags assignment to the Instance global', async () => {
    const f = await scan('Instance = decoded', '.lua');
    assert.ok(f.some(x => x.rule === 'ROBLOX_GLOBAL_SHADOW'));
  });

  it('flags the off-script attribute payload loader (attr read + decode loop)', async () => {
    const src = [
      'local nopxd = script.PlaneConstraint:GetAttribute("a")',
      'local Nahhh = ""',
      'for i = 1, #nopxd do Nahhh = nopxd:sub(i, i) .. Nahhh end',
    ].join('\n');
    const f = await scan(src, '.lua');
    assert.ok(f.some(x => x.rule === 'ROBLOX_ATTRIBUTE_PAYLOAD_LOADER' && x.severity === 'high'));
  });

  it('does not flag `local Instance = ...` as a global shadow', async () => {
    const f = await scan('local Instance = require(game.ReplicatedStorage.Helper)', '.lua');
    assert.equal(f.filter(x => x.rule === 'ROBLOX_GLOBAL_SHADOW').length, 0);
  });

  it('stays quiet on benign Luau', async () => {
    const benign = [
      'local part = Instance.new("Part")',
      'part.Anchored = true',
      'part.Parent = workspace',
      'local function add(a, b) return a + b end',
      'print(add(1, 2))',
    ].join('\n');
    const f = await scan(benign, '.luau');
    assert.equal(f.length, 0, 'benign Luau should produce no findings');
  });
});

describe('RobloxSecurityAgent — dual-use gating', () => {
  it('softens an isolated loadstring in first-party Lua to medium', async () => {
    const f = await scan('local fn = loadstring(userInput)', '.lua');
    const ls = f.find(x => x.rule === 'ROBLOX_LOADSTRING');
    assert.ok(ls, 'should still report loadstring');
    assert.equal(ls.severity, 'medium');
  });

  it('elevates loadstring when it co-occurs with a definite IOC', async () => {
    const src = [
      "local a = game:GetObjects('rbxassetid://999')[1]",
      'local fn = loadstring(decoded)',
    ].join('\n');
    const f = await scan(src, '.lua');
    const ls = f.find(x => x.rule === 'ROBLOX_LOADSTRING');
    assert.ok(ls);
    assert.equal(ls.severity, 'high');
    assert.equal(ls.confidence, 'high');
  });

  it('keeps HttpEnabled high when it comes from an inserted .rbxmx asset', async () => {
    const xml = [
      '<roblox version="4"><Item class="Script"><Properties>',
      '<ProtectedString name="Source">game.HttpService.HttpEnabled = true</ProtectedString>',
      '</Properties></Item></roblox>',
    ].join('\n');
    const f = await scan(xml, '.rbxmx');
    const http = f.find(x => x.rule === 'ROBLOX_HTTP_ENABLE');
    assert.ok(http);
    assert.equal(http.severity, 'high');
    assert.equal(http.confidence, 'high');
  });
});

describe('RobloxSecurityAgent — .rbxmx XML', () => {
  it('decodes embedded <ProtectedString> script source and flags IOCs', async () => {
    const xml = [
      '<roblox version="4">',
      '<Item class="LocalScript">',
      '<Properties>',
      "<ProtectedString name=\"Source\">local a = game:GetObjects(&apos;rbxassetid://999&apos;)</ProtectedString>",
      '</Properties>',
      '</Item>',
      '</roblox>',
    ].join('\n');
    const f = await scan(xml, '.rbxmx');
    assert.ok(f.some(x => x.rule === 'ROBLOX_RUNTIME_ASSET_FETCH'));
  });

  it('decodes a base64 AttributesSerialize blob and flags a hidden payload', async () => {
    // Simulate Roblox attribute container bytes wrapping a payload string.
    const blob = Buffer.concat([
      Buffer.from([0x01, 0x61, 0x00]),
      Buffer.from('rbxassetid://114706280708394'),
    ]).toString('base64');
    const xml = [
      '<roblox version="4">',
      '<Item class="PlaneConstraint">',
      '<Properties>',
      `<BinaryString name="AttributesSerialize">${blob}</BinaryString>`,
      '</Properties>',
      '</Item>',
      '</roblox>',
    ].join('\n');
    const f = await scan(xml, '.rbxmx');
    assert.ok(f.some(x => x.rule === 'ROBLOX_ATTRIBUTE_PAYLOAD' && x.severity === 'critical'));
  });

  it('flags a reversed payload stored in an attribute', async () => {
    const reversed = 'rbxassetid://777'.split('').reverse().join('');
    const blob = Buffer.from(reversed).toString('base64');
    const xml = `<roblox><Item class="Part"><Properties><BinaryString name="AttributesSerialize">${blob}</BinaryString></Properties></Item></roblox>`;
    const f = await scan(xml, '.rbxmx');
    assert.ok(f.some(x => x.rule === 'ROBLOX_ATTRIBUTE_PAYLOAD'));
  });
});

describe('RobloxSecurityAgent — ClickFix lure', () => {
  it('flags a fake-error paste-and-run lure', async () => {
    const lure = [
      'Error 501',
      'Something went wrong with this game.',
      'To fix this, copy the text in the textbox and paste it into the command bar.',
      '(Ctrl+C -> Shift+F5 -> Ctrl+V -> Press Enter)',
    ].join('\n');
    const f = await scan(lure, '.txt');
    assert.ok(f.some(x => x.rule === 'CLICKFIX_PASTE_RUN' && x.severity === 'high'));
  });

  it('does not flag an ordinary error message with no paste instruction', async () => {
    const f = await scan('Error 500: internal server error. Check the logs.', '.txt');
    assert.equal(f.filter(x => x.rule === 'CLICKFIX_PASTE_RUN').length, 0);
  });
});
