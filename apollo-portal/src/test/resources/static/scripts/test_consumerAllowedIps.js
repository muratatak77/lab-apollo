/*
 * Copyright 2026 Apollo Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');
const source = fs.readFileSync(path.resolve(__dirname,
    '../../../../main/resources/static/scripts/services/ConsumerService.js'), 'utf8');
let consumerService;
vm.runInNewContext(source, { appService: { service: (name, definition) => {
    if (name === 'ConsumerService') {
        consumerService = definition.at(-1)(() => ({}), {}, { prefixPath: () => '' });
    }
} } });

test('splits allowed ips by comma, semicolon and whitespace', () => {
    assert.deepEqual(Array.from(consumerService.parseAllowedIps(' 10.0.0.0/8,192.168.1.10\n::1;\t2001:db8::/32 ')),
        ['10.0.0.0/8', '192.168.1.10', '::1', '2001:db8::/32']);
});

test('drops empty and duplicated allowed ips', () => {
    assert.deepEqual(Array.from(consumerService.parseAllowedIps('10.0.0.1,, 10.0.0.1\n\n')), ['10.0.0.1']);
    assert.deepEqual(Array.from(consumerService.parseAllowedIps('')), []);
    assert.deepEqual(Array.from(consumerService.parseAllowedIps(undefined)), []);
});

test('formats allowed ips from consumer info list and persisted token value', () => {
    assert.equal(consumerService.formatAllowedIps(['10.0.0.0/8', '::1']), '10.0.0.0/8, ::1');
    assert.equal(consumerService.formatAllowedIps('10.0.0.0/8,::1'), '10.0.0.0/8, ::1');
    assert.equal(consumerService.formatAllowedIps(null), '');
});
