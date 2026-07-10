
// Copyright © 2025–2026 Stefano Noferi & Admina contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeOperationError,
} from 'n8n-workflow';

export class AdminaGovern implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Admina Govern',
		name: 'adminaGovern',
		icon: 'file:admina-govern.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["checkMode"]}} governance check',
		description: 'Validate workflow data through the Admina governance proxy for PII redaction, firewall enforcement, and compliance.',
		defaults: {
			name: 'Admina Govern',
		},
		inputs: ['main'],
		outputs: ['main'],
		credentials: [
			{
				name: 'adminaApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Check Mode',
				name: 'checkMode',
				type: 'options',
				options: [
					{ name: 'Input', value: 'input', description: 'Validate inbound data before processing' },
					{ name: 'Output', value: 'output', description: 'Validate outbound data before delivery' },
					{ name: 'Both', value: 'both', description: 'Validate in both directions' },
				],
				default: 'input',
				description: 'When to apply governance checks',
			},
			{
				displayName: 'Content Field',
				name: 'contentField',
				type: 'string',
				default: 'text',
				description: 'JSON field name containing the text to validate',
			},
			{
				displayName: 'On Block',
				name: 'onBlock',
				type: 'options',
				options: [
					{ name: 'Stop Workflow', value: 'stop', description: 'Halt the workflow execution' },
					{ name: 'Raise Error', value: 'error', description: 'Throw an error node' },
					{ name: 'Skip Item', value: 'skip', description: 'Remove the blocked item from output' },
				],
				default: 'stop',
				description: 'Action to take when content is blocked',
			},
			{
				displayName: 'Domain Options',
				name: 'domainOptions',
				type: 'collection',
				placeholder: 'Configure Domains',
				default: {},
				options: [
					{
						displayName: 'Firewall',
						name: 'firewall',
						type: 'boolean',
						default: true,
						description: 'Whether to enable injection detection',
					},
					{
						displayName: 'PII Redaction',
						name: 'piiRedaction',
						type: 'boolean',
						default: true,
						description: 'Whether to enable PII detection and redaction',
					},
					{
						displayName: 'Loop Breaker',
						name: 'loopBreaker',
						type: 'boolean',
						default: true,
						description: 'Whether to enable loop detection',
					},
					{
						displayName: 'EU AI Act',
						name: 'euAiAct',
						type: 'boolean',
						default: true,
						description: 'Whether to enable EU AI Act classification',
					},
				],
			},
			{
				displayName: 'Log to Forensic',
				name: 'logToForensic',
				type: 'boolean',
				default: true,
				description: 'Whether to log this validation to the forensic black box',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const credentials = await this.getCredentials('adminaApi');
		const proxyUrl = credentials.proxyUrl as string;
		const apiKey = credentials.apiKey as string;
		const contentField = this.getNodeParameter('contentField', 0) as string;
		const onBlock = this.getNodeParameter('onBlock', 0) as string;
		const logToForensic = this.getNodeParameter('logToForensic', 0) as boolean;

		const results: INodeExecutionData[] = [];

		for (let i = 0; i < items.length; i++) {
			const item = items[i];
			const content = (item.json[contentField] as string) ?? '';

			if (!content) {
				results.push(item);
				continue;
			}

			const headers: Record<string, string> = {
				'Content-Type': 'application/json',
			};
			if (apiKey) {
				headers['X-API-Key'] = apiKey;
			}

			const response = await this.helpers.httpRequest({
				method: 'POST',
				url: `${proxyUrl}/api/v1/validate`,
				headers,
				body: {
					content,
					session_id: `n8n-${this.getNode().id}`,
				},
				json: true,
			});

			const action = response.action as string;

			if (action === 'BLOCK') {
				if (onBlock === 'stop') {
					throw new NodeOperationError(
						this.getNode(),
						`Content blocked by Admina governance: ${JSON.stringify(response.checks)}`,
						{ itemIndex: i },
					);
				} else if (onBlock === 'error') {
					throw new NodeOperationError(
						this.getNode(),
						'Admina governance blocked this content',
						{ itemIndex: i },
					);
				}
				// skip — do not add to results
				continue;
			}

			const outputItem: INodeExecutionData = {
				json: {
					...item.json,
					_admina: {
						action,
						risk_level: response.risk_level,
						checks: response.checks,
						latency_ms: response.latency_ms,
					},
				},
			};

			if (action === 'REDACT' && response.redacted_content) {
				outputItem.json[contentField] = response.redacted_content;
			}

			results.push(outputItem);

			if (logToForensic) {
				try {
					await this.helpers.httpRequest({
						method: 'POST',
						url: `${proxyUrl}/api/v1/audit`,
						headers,
						body: {
							event: {
								action: 'n8n_govern',
								node_id: this.getNode().id,
								workflow_action: action,
								risk_level: response.risk_level,
								item_index: i,
							},
						},
						json: true,
					});
				} catch {
					// Forensic logging is best-effort; do not fail the workflow
				}
			}
		}

		return [results];
	}
}
