from services.recommendations import build_recommendations
from services.security_scanner import scan_domain


domain = "example.com"

print("Running CyberShield scan...")
result = scan_domain(domain)

print("\n===== SCAN RESULT =====")
print(result)

print("\n===== RECOMMENDATIONS =====")
recommendations = build_recommendations(result)

for recommendation in recommendations:
    print("\nTitle:", recommendation["title"])
    print("Why:", recommendation["why"])
    print("Action:", recommendation["action"])

print("\nTotal recommendations:", len(recommendations))