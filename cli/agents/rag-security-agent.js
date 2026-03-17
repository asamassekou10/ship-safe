/**
 * RAG Security Agent
 * ====================
 *
 * Detects security vulnerabilities in Retrieval-Augmented Generation
 * (RAG) implementations. RAG poisoning attacks are a proven threat
 * vector — attackers corrupt knowledge bases to manipulate LLM outputs.
 *
 * Checks: unvalidated document ingestion, missing chunk isolation,
 * embedding exposure, metadata leakage, no retrieval filtering,
 * excessive context stuffing.
 *
 * Maps to: OWASP LLM08 (Vector & Embedding Weaknesses),
 *          OWASP Agentic AI ASI04 (Memory Poisoning)
 */

import path from 'path';
import { BaseAgent } from './base-agent.js';

// =============================================================================
// RAG SECURITY PATTERNS
// =============================================================================

const PATTERNS = [
  // ── Document Ingestion ───────────────────────────────────────────────────
  {
    rule: 'RAG_UNSANITIZED_INGESTION',
    title: 'RAG: Documents Ingested Without Sanitization',
    regex: /(?:addDocuments|add_documents|upsert|insert|index\.add|from_documents)\s*\(\s*(?:documents|docs|chunks|texts|pages|uploads|files|userDocs|userFiles)/g,
    severity: 'high',
    cwe: 'CWE-20',
    owasp: 'A03:2021',
    description: 'Documents added to vector store without sanitization. Attackers can embed malicious instructions in documents that get retrieved and injected into LLM context.',
    fix: 'Sanitize document content before ingestion: strip HTML/script tags, detect prompt injection patterns, validate content type.',
  },
  {
    rule: 'RAG_USER_UPLOAD_TO_VECTORDB',
    title: 'RAG: User Upload Directly to Vector Store',
    regex: /(?:upload|multer|formidable|busboy|req\.file|req\.files)[\s\S]{0,500}(?:addDocuments|add_documents|upsert|vectorStore|index\.add|embed|from_documents)/g,
    severity: 'critical',
    cwe: 'CWE-434',
    owasp: 'A03:2021',
    description: 'User file uploads are fed directly into a vector database without review. This enables RAG poisoning — attackers upload documents containing hidden instructions.',
    fix: 'Add a review/approval pipeline between user uploads and vector store ingestion. Scan uploads for prompt injection patterns.',
  },
  {
    rule: 'RAG_NO_CONTENT_FILTER',
    title: 'RAG: No Content Filtering on Ingestion',
    regex: /(?:TextLoader|PDFLoader|CSVLoader|DirectoryLoader|WebBaseLoader|UnstructuredLoader|load_and_split|loadDocuments)\s*\((?![\s\S]{0,300}(?:filter|sanitize|clean|validate|strip|remove|moderate))/g,
    severity: 'medium',
    cwe: 'CWE-20',
    owasp: 'A03:2021',
    confidence: 'medium',
    description: 'Document loaders used without content filtering. Loaded content goes directly to embedding/vector store.',
    fix: 'Add content filtering after loading documents: remove scripts, detect injection patterns, validate format.',
  },

  // ── Chunk Isolation ──────────────────────────────────────────────────────
  {
    rule: 'RAG_NO_TENANT_ISOLATION',
    title: 'RAG: Vector Store Without Tenant Isolation',
    regex: /(?:vectorStore|pinecone|chroma|weaviate|qdrant|milvus|pgvector)[\s\S]{0,300}(?:add|upsert|insert|index)(?![\s\S]{0,200}(?:namespace|tenant|partition|collection|filter|user_id|org_id|metadata.*(?:user|tenant|org)))/g,
    severity: 'high',
    cwe: 'CWE-284',
    owasp: 'A01:2021',
    confidence: 'medium',
    description: 'Documents stored in vector database without tenant/user isolation. Users can retrieve other users\' private documents.',
    fix: 'Use namespaces, collections, or metadata filters to isolate documents by tenant/user.',
  },
  {
    rule: 'RAG_SYSTEM_DOCS_WITH_USER_DOCS',
    title: 'RAG: System Documents Mixed With User Documents',
    regex: /(?:addDocuments|add_documents|upsert)[\s\S]{0,200}(?:system|internal|private|admin)[\s\S]{0,200}(?:user|public|external|upload)/g,
    severity: 'medium',
    cwe: 'CWE-668',
    owasp: 'A01:2021',
    confidence: 'low',
    description: 'System/internal documents mixed with user documents in the same collection. User queries could retrieve sensitive internal docs.',
    fix: 'Separate system documents from user documents in different collections or namespaces.',
  },

  // ── Retrieval & Query Safety ─────────────────────────────────────────────
  {
    rule: 'RAG_NO_RETRIEVAL_FILTER',
    title: 'RAG: Retrieved Chunks Used Without Filtering',
    regex: /(?:similarity_search|similaritySearch|query|retrieve|get_relevant|asRetriever)[\s\S]{0,300}(?:page_content|pageContent|text|content|document)[\s\S]{0,200}(?:prompt|messages|content|system|user)/g,
    severity: 'high',
    cwe: 'CWE-74',
    owasp: 'A03:2021',
    confidence: 'medium',
    description: 'Retrieved document chunks injected into LLM prompt without filtering. Poisoned documents can override system instructions.',
    fix: 'Filter retrieved chunks: remove instruction-like content, apply relevance score thresholds, limit number of chunks.',
  },
  {
    rule: 'RAG_NO_RELEVANCE_THRESHOLD',
    title: 'RAG: No Relevance Score Threshold on Retrieval',
    regex: /(?:similarity_search|similaritySearch|asRetriever)\s*\(\s*(?:query|question|input)(?![\s\S]{0,200}(?:score_threshold|scoreThreshold|threshold|minScore|min_score|filter))/g,
    severity: 'medium',
    cwe: 'CWE-20',
    owasp: 'A03:2021',
    confidence: 'low',
    description: 'Vector similarity search without relevance threshold. Low-relevance chunks may contain poisoned content designed to be retrieved for many queries.',
    fix: 'Set a minimum relevance score threshold to filter out low-quality matches.',
  },
  {
    rule: 'RAG_EXCESSIVE_CONTEXT',
    title: 'RAG: Excessive Retrieved Context',
    regex: /(?:k\s*[:=]\s*(?:[5-9]\d|\d{3,})|top_k\s*[:=]\s*(?:[5-9]\d|\d{3,})|search_kwargs.*k.*(?:[5-9]\d|\d{3,}))/g,
    severity: 'medium',
    cwe: 'CWE-400',
    owasp: 'A04:2021',
    confidence: 'low',
    description: 'Retrieving a very large number of chunks (50+). Increases the attack surface for prompt injection via poisoned documents.',
    fix: 'Limit retrieved chunks to the minimum needed (typically 3-10). More chunks = more injection surface.',
  },

  // ── Embedding & Data Exposure ────────────────────────────────────────────
  {
    rule: 'RAG_EMBEDDING_API_EXPOSED',
    title: 'RAG: Embedding Endpoint Exposed Without Auth',
    regex: /(?:app\.|router\.|api\.)(?:get|post)\s*\(\s*['"].*(?:embed|embedding|vectorize|encode)['"](?![\s\S]{0,300}(?:auth|middleware|protect|guard|jwt|bearer|session))/g,
    severity: 'high',
    cwe: 'CWE-306',
    owasp: 'A07:2021',
    confidence: 'medium',
    description: 'Embedding API endpoint exposed without authentication. Attackers can enumerate embeddings or generate vectors for injection attacks.',
    fix: 'Add authentication middleware to embedding endpoints.',
  },
  {
    rule: 'RAG_METADATA_IN_RESPONSE',
    title: 'RAG: Internal Metadata Exposed in Response',
    regex: /(?:metadata|source|file_path|filePath|url|author|timestamp)[\s\S]{0,100}(?:res\.json|res\.send|response\.json|return\s*\{|jsonify)/g,
    severity: 'medium',
    cwe: 'CWE-200',
    owasp: 'A01:2021',
    confidence: 'low',
    description: 'Internal document metadata (file paths, sources, authors) returned in API responses. Leaks information about the knowledge base structure.',
    fix: 'Strip internal metadata before returning responses. Only expose necessary fields to the client.',
  },
  {
    rule: 'RAG_EMBEDDING_IN_RESPONSE',
    title: 'RAG: Raw Embeddings Returned to Client',
    regex: /(?:embedding|vector|dense_vector)[\s\S]{0,100}(?:res\.json|res\.send|response|return|output)/g,
    severity: 'medium',
    cwe: 'CWE-200',
    owasp: 'A01:2021',
    confidence: 'low',
    description: 'Raw embedding vectors returned in API responses. Research shows embeddings can be inverted to recover original text, leaking private data.',
    fix: 'Never return raw embedding vectors in API responses. Embeddings should remain server-side only.',
  },

  // ── Model & Pipeline Safety ──────────────────────────────────────────────
  {
    rule: 'RAG_PICKLE_EMBEDDING_MODEL',
    title: 'RAG: Embedding Model Loaded via Pickle',
    regex: /(?:torch\.load|pickle\.load|joblib\.load)\s*\(\s*(?!.*safetensors)(?!.*weights_only\s*=\s*True)/g,
    severity: 'critical',
    cwe: 'CWE-502',
    owasp: 'A08:2021',
    description: 'ML model loaded from pickle format. Pickle files can contain arbitrary code that executes on load.',
    fix: 'Use safetensors format for model loading. If using torch.load(), set weights_only=True.',
  },
  {
    rule: 'RAG_TRUST_REMOTE_CODE',
    title: 'RAG: Model Loaded With trust_remote_code=True',
    regex: /trust_remote_code\s*=\s*True/g,
    severity: 'high',
    cwe: 'CWE-94',
    owasp: 'A08:2021',
    description: 'Embedding or LLM model loaded with trust_remote_code=True. Allows execution of arbitrary code from the model repository.',
    fix: 'Set trust_remote_code=False. Audit model code before enabling remote code execution.',
  },
];

// =============================================================================
// RAG SECURITY AGENT
// =============================================================================

export class RAGSecurityAgent extends BaseAgent {
  constructor() {
    super(
      'RAGSecurityAgent',
      'Detect RAG security vulnerabilities — poisoning, embedding exposure, tenant isolation gaps',
      'llm'
    );
  }

  async analyze(context) {
    const { files } = context;

    const codeFiles = files.filter(f => {
      const ext = path.extname(f).toLowerCase();
      return ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.rb', '.go', '.java'].includes(ext);
    });

    let findings = [];
    for (const file of codeFiles) {
      findings = findings.concat(this.scanFileWithPatterns(file, PATTERNS));
    }
    return findings;
  }
}

export default RAGSecurityAgent;
