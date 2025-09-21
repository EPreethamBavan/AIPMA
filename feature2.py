from gemini import GeminiHandler
from chroma import ChromadbHandler
from volatility import VolatilityPluginRunner
# Initialize handlers
volatility_runner = VolatilityPluginRunner()
chroma_handler = ChromadbHandler()
gemini_handler = GeminiHandler()

# Run Volatility plugins
file_path = r"C:\Users\preet\Downloads\Challenge_NotchItUp\Challenge.raw"  # Replace with actual file path
results, metadata = volatility_runner.run_all_plugins(file_path)
print(metadata)
# Prepare documents, metadata, and IDs for embedding
documents = []
embed_metadata = []
ids = []

for pid, data in results.items():
    # Create a document string from the results
    doc = f"PID: {pid}\n"
    for plugin, entries in data.items():
        doc += f"{plugin}:\n"
        for entry in entries:
            doc += f"{entry}\n"
    documents.append(doc)
    embed_metadata.append(metadata[pid])
    ids.append(str(pid))

# Embed the results and metadata
chroma_handler.embed(documents, embed_metadata, ids)

# Get user query
user_query = input("Enter your query: ")

# Query ChromaDB for top 3 results
query_results = chroma_handler.query(user_query)

# Prepare context for Gemini
context = f"User Query: {user_query}\n\nTop 3 Matching Documents:\n"
for i, (doc, dist, meta) in enumerate(zip(query_results["documents"][0], query_results["distances"][0], query_results["metadatas"][0])):
    context += f"\nResult {i+1}:\n"
    context += f"Document: {doc}\n"
    context += f"Distance: {dist:.4f}\n"
    context += f"Metadata: {meta}\n"
print(context)
# Query Gemini for final answer
system_prompt = "You are a helpful assistant analyzing Volatility plugin results. Provide a concise answer based on the user query and the provided context."
final_answer = gemini_handler.query(system_prompt, context)

print("\nFinal Answer:")
print(final_answer)

# Clean up
chroma_handler.delete_collection()