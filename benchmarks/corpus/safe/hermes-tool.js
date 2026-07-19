import { toolRegistry } from '@nousresearch/hermes-agent';
const allowedTools = new Set(['search', 'status']);
if (allowedTools.has(response.name)) toolRegistry[response.name](response.args);
