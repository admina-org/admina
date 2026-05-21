
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
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class AdminaApi implements ICredentialType {
	name = 'adminaApi';
	displayName = 'Admina API';
	documentationUrl = 'https://admina.org/docs/n8n';

	properties: INodeProperties[] = [
		{
			displayName: 'Proxy URL',
			name: 'proxyUrl',
			type: 'string',
			default: 'http://localhost:8080',
			placeholder: 'http://localhost:8080',
			description: 'Base URL of the Admina governance proxy',
			required: true,
		},
		{
			displayName: 'API Key',
			name: 'apiKey',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			description: 'Optional API key for authenticated access',
		},
	];
}
