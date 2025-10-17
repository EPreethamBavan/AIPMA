import os

import chromadb
from chromadb.utils import embedding_functions
from dotenv import load_dotenv


class ChromadbHandler:
    def __init__(self):

        load_dotenv()
        self.client = chromadb.Client()
        self.collection = self.client.create_collection(name="AIPMA")
        model = os.getenv("EMMBEDDING_MODEL")
        self.embedding_function = (
            embedding_functions.GoogleGenerativeAiEmbeddingFunction(
                api_key="<api_key>", model_name=model
            )
        )

    def embed(self, documents, metadata, ids):

        embeddings = self.embedding_function(documents)

        # Add documents, embeddings, and metadata to the collection
        self.collection.add(
            documents=documents, embeddings=embeddings, metadatas=metadata, ids=ids
        )

    def query(self, query_text):
        query_embedding = self.embedding_function([query_text])[0]

        # Perform the query
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=10,  # Return top 10 similar documents
        )
        return results
        """ print("Query: ", query_text)
        print("\nTop matching documents:")
        for i, (doc, dist, meta) in enumerate(zip(results["documents"][0], results["distances"][0], results["metadatas"][0])):
            print(f"\nResult {i+1}:")
            print(f"Document: {doc}")
            print(f"Distance: {dist:.4f}")
            print(f"Metadata: {meta}")"""

    def delete_collection(self):
        self.client.delete_collection(name="AIPMA")
