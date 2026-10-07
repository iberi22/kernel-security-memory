# Comparación de siete enfoques de recuperación

Fecha de investigación: 2026-10-07. Seleccionados por los requisitos, no un top global ni ranking empírico. Son métodos, runtimes y frameworks de tipos diferentes. Capacidades declaradas provienen de fuentes primarias; la recomendación es una inferencia de diseño.

| Candidato | Tipo | Indexación de código | Infraestructura | Límite | Lógica aprovechable |
|---|---|---|---|---|---|
| [Xavier](https://github.com/iberi22/xavier) | Runtime de memoria + CodeGraph | Parser C Tree-sitter verificado en código; símbolos por archivo | SQLite/FTS5 + sqlite-vec; embeddings opcionales | Falta puente probado al corpus temporal; AST no prueba seguridad | Exacto/BM25/vector + RRF y divulgación progresiva |
| [Vul-RAG](https://github.com/KnowledgeRAG4LLMVulD/KnowledgeRAG4LLMVulD) | Método de investigación de vulnerabilidades | Conocimiento causal y pares Linux antes/después | Extracción y verificación LLM; evaluar adaptación local | No seguimiento completo de evolución; resultados no garantizan transferencia | Causa/precondiciones/solución e indicadores por pares |
| [Microsoft GraphRAG](https://github.com/microsoft/graphrag) | Pipeline de grafo para texto | Entidades, relaciones, claims y comunidades; sin AST de Linux | Extracción/resúmenes LLM y almacenamiento derivado | Upstream en maintenance mode; no elegir como núcleo sin valorar mantenimiento | Vistas globales por familia/subsistema sobre hechos verificados |
| [LightRAG](https://github.com/HKUDS/LightRAG) | Motor grafo + vectores | Fragmentación textual; adaptación AST necesaria | LLM/embeddings + stores; incremental | Relaciones extraídas por modelo requieren validación | Recuperación local/global e incremento del índice |
| [LlamaIndex](https://developers.llamaindex.ai/python/framework/module_guides/indexing/lpg_index_guide/) | Framework de índices/recuperadores | CodeSplitter AST + PropertyGraph con esquema/extractores | Python y backend elegido; extractores deterministas posibles | No especialista ni historial de parches listo | Unidades AST, esquema tipado, composición de recuperadores |
| [LangGraph](https://docs.langchain.com/oss/python/langgraph/agentic-rag) | Orquestación agentica | No indexa código por sí mismo | Backend externo y llamadas por vuelta | Grafo de ejecución no es grafo de conocimiento | Buscar/comprobar/ampliar/abstenerse con presupuesto |
| [PageIndex](https://github.com/VectifyAI/PageIndex) | Árbol documental con navegación razonada | Orientado a documentos; AST no demostrado | Sin vector DB; razonamiento con modelo | Benchmarks documentales no trasladables a seguridad Linux | Jerarquía subsistema/archivo/símbolo y lectura exacta |

## Recomendación provisional

Usar un solo flujo de recuperación de evidencia temporal y código: exacto + léxico + vectores opcionales, RRF, expansión de vecinos tipados y verificación acotada. Xavier aporta integración con los agentes existentes; el corpus JSON/SQL debe seguir independiente. Vul-RAG aporta la ficha causal; LlamaIndex, el diseño AST/graph tipado; LightRAG, recuperación local/global e incremental; LangGraph, el ciclo con abstención; PageIndex, navegación jerárquica. Las comunidades de GraphRAG son una vista adicional posible, no la fuente canónica.

No instalar los siete ni copiar sus implementaciones para probar la idea inicial. Primero medir las logicas base con el mismo corpus; las implementaciones completas que no se ejecuten deben marcarse NOT_RUN. No hay puntuaciones inventadas de precisión/costo ni ganador definitivo.

## Evidencia de Xavier

Se verificaron `code-graph/src/parser/c.rs` (Tree-sitter C), documentación de búsqueda híbrida y ADR-036 de navegación por árboles. Existe infraestructura reutilizable, pero el módulo CVE actual es un mock y el corpus temporal no está conectado. La licencia raíz de Xavier es AGPL/comercial; no asumir MIT por un README de submódulo. Integración HTTP primero; revisar licencias de archivos antes de copiar código.

## Fuentes adicionales y reproducibilidad

- [LlamaIndex CodeSplitter, código original](https://raw.githubusercontent.com/run-llama/llama_index/main/llama-index-core/llama_index/core/node_parser/text/code.py)
- [LightRAG, paper original](https://arxiv.org/abs/2410.05779)
- [GraphRAG: pipeline oficial](https://microsoft.github.io/graphrag/index/overview/)
- [Vul-RAG, paper original](https://arxiv.org/abs/2406.11147)
- [Replicación de Vul-RAG](https://arxiv.org/abs/2606.04739): motiva medir discriminación por pares y transferencia; sus resultados no son métricas de este proyecto.

Los enlaces de ramas `main` son descubrimiento mutable. El experimento debe fijar commits/versiones reales de todo código que ejecute. No se descargaron datasets ni modelos grandes en la máquina del usuario.
