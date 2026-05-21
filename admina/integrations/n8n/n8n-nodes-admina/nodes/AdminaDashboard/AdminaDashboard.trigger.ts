
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
	ITriggerFunctions,
	INodeType,
	INodeTypeDescription,
	ITriggerResponse,
} from 'n8n-workflow';

import WebSocket from 'ws';

export class AdminaDashboard implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Admina Dashboard',
		name: 'adminaDashboard',
		icon: 'file:admina-dashboard.svg',
		group: ['trigger'],
		version: 1,
		subtitle: 'Live governance events',
		description: 'Trigger workflows when Admina detects governance events via WebSocket live feed.',
		defaults: {
			name: 'Admina Dashboard',
		},
		inputs: [],
		outputs: ['main'],
		credentials: [
			{
				name: 'adminaApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Event Filter',
				name: 'eventFilter',
				type: 'multiOptions',
				options: [
					{ name: 'Block', value: 'BLOCK', description: 'Content or action was blocked' },
					{ name: 'Critical', value: 'CRITICAL', description: 'Critical security event' },
					{ name: 'PII Detected', value: 'PII_DETECTED', description: 'PII was detected and redacted' },
					{ name: 'Loop Detected', value: 'LOOP_DETECTED', description: 'Repetitive request loop detected' },
					{ name: 'Compliance Gap', value: 'COMPLIANCE_GAP', description: 'EU AI Act compliance gap found' },
				],
				default: ['BLOCK', 'CRITICAL'],
				description: 'Which governance events should trigger this workflow',
			},
			{
				displayName: 'Reconnect Interval (s)',
				name: 'reconnectInterval',
				type: 'number',
				default: 5,
				description: 'Seconds to wait before reconnecting after a disconnect',
			},
		],
	};

	async trigger(this: ITriggerFunctions): Promise<ITriggerResponse> {
		const credentials = await this.getCredentials('adminaApi');
		const proxyUrl = (credentials.proxyUrl as string).replace(/\/$/, '');
		const apiKey = credentials.apiKey as string;
		const eventFilter = this.getNodeParameter('eventFilter') as string[];
		const reconnectInterval = this.getNodeParameter('reconnectInterval') as number;

		const wsUrl = proxyUrl.replace(/^http/, 'ws') + '/api/dashboard/live';

		let ws: WebSocket | null = null;
		let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
		let shouldReconnect = true;

		const connect = (): void => {
			const headers: Record<string, string> = {};
			if (apiKey) {
				headers['X-API-Key'] = apiKey;
			}

			ws = new WebSocket(wsUrl, { headers });

			ws.on('message', (data: WebSocket.Data) => {
				try {
					const event = JSON.parse(data.toString());
					const eventType: string = event.event_type ?? '';

					// Apply event filter
					if (eventFilter.length > 0 && !eventFilter.includes(eventType)) {
						return;
					}

					this.emit([
						this.helpers.returnJsonArray([event]),
					]);
				} catch {
					// Ignore malformed messages
				}
			});

			ws.on('close', () => {
				if (shouldReconnect) {
					reconnectTimer = setTimeout(connect, reconnectInterval * 1000);
				}
			});

			ws.on('error', () => {
				// Will trigger 'close' event, which handles reconnection
			});
		};

		connect();

		const closeFunction = async (): Promise<void> => {
			shouldReconnect = false;
			if (reconnectTimer) {
				clearTimeout(reconnectTimer);
			}
			if (ws) {
				ws.close();
			}
		};

		return {
			closeFunction,
		};
	}
}
