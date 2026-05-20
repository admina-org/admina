
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
} from 'n8n-workflow';

export class AdminaAudit implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Admina Audit',
		name: 'adminaAudit',
		icon: 'file:admina-audit.svg',
		group: ['output'],
		version: 1,
		subtitle: 'Log to forensic black box',
		description: 'Log workflow execution events to the Admina forensic black box for immutable audit trailing.',
		defaults: {
			name: 'Admina Audit',
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
				displayName: 'Risk Classification',
				name: 'riskClassification',
				type: 'options',
				options: [
					{ name: 'High', value: 'high', description: 'High-risk AI system (Art. 6)' },
					{ name: 'Limited', value: 'limited', description: 'Limited-risk system (Art. 52)' },
					{ name: 'Minimal', value: 'minimal', description: 'Minimal-risk system' },
				],
				default: 'limited',
				description: 'EU AI Act risk classification for this workflow',
			},
			{
				displayName: 'Event Action',
				name: 'eventAction',
				type: 'string',
				default: 'workflow_execution',
				description: 'Action type label for the audit record',
			},
			{
				displayName: 'Custom Metadata',
				name: 'customMetadata',
				type: 'fixedCollection',
				placeholder: 'Add Metadata',
				typeOptions: {
					multipleValues: true,
				},
				default: {},
				options: [
					{
						name: 'entries',
						displayName: 'Metadata Entry',
						values: [
							{
								displayName: 'Key',
								name: 'key',
								type: 'string',
								default: '',
							},
							{
								displayName: 'Value',
								name: 'value',
								type: 'string',
								default: '',
							},
						],
					},
				],
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const credentials = await this.getCredentials('adminaApi');
		const proxyUrl = credentials.proxyUrl as string;
		const apiKey = credentials.apiKey as string;
		const riskClassification = this.getNodeParameter('riskClassification', 0) as string;
		const eventAction = this.getNodeParameter('eventAction', 0) as string;
		const customMetadataParam = this.getNodeParameter('customMetadata', 0) as {
			entries?: Array<{ key: string; value: string }>;
		};

		const headers: Record<string, string> = {
			'Content-Type': 'application/json',
		};
		if (apiKey) {
			headers['X-API-Key'] = apiKey;
		}

		const customMetadata: Record<string, string> = {};
		if (customMetadataParam.entries) {
			for (const entry of customMetadataParam.entries) {
				if (entry.key) {
					customMetadata[entry.key] = entry.value;
				}
			}
		}

		const results: INodeExecutionData[] = [];

		for (let i = 0; i < items.length; i++) {
			const item = items[i];

			let auditResult: Record<string, unknown> = { recorded: false };

			try {
				const response = await this.helpers.httpRequest({
					method: 'POST',
					url: `${proxyUrl}/api/v1/audit`,
					headers,
					body: {
						event: {
							action: eventAction,
							source: 'n8n',
							node_id: this.getNode().id,
							workflow_id: this.getWorkflow().id,
							item_index: i,
							risk_classification: riskClassification,
							item_keys: Object.keys(item.json),
							...customMetadata,
						},
					},
					json: true,
				});
				auditResult = response;
			} catch {
				auditResult = { recorded: false, error: 'Admina proxy unreachable' };
			}

			results.push({
				json: {
					...item.json,
					_admina_audit: auditResult,
				},
			});
		}

		return [results];
	}
}
