from gemini import GeminiHandler
from volatility import VolatilityPluginRunner
from router import QueryRouter
# Assume these are initialized as before

# 1. Run Volatility to get the data
volatility_runner = VolatilityPluginRunner()
file_path = r"C:\Users\preet\Downloads\Challenge_NotchItUp\Challenge.raw"
results, metadata = volatility_runner.run_all_plugins(file_path)

# 2. Initialize the handlers and router
gemini_handler = GeminiHandler()
router = QueryRouter(gemini_handler, metadata, results)

# 3. Start the query loop
while True:
    user_query = input("\nEnter your query (or 'exit'): ")
    if user_query.lower() == 'exit':
        break
        
    final_answer = router.route_query(user_query)
    print("\n✅ Final Answer:")
    print(final_answer)