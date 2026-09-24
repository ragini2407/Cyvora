from groq import Groq
from django.conf import settings

client = Groq(api_key=settings.GROQ_API_KEY)


def generate_ai_summary_and_recommendation(cve_id, description, severity, cvss_score):
    prompt = f"""You are a cybersecurity analyst. Given the following vulnerability, provide:
1. A simple 2-3 sentence summary in plain, non-technical language.
2. A short, actionable mitigation recommendation (2-3 sentences).

CVE ID: {cve_id}
Severity: {severity}
CVSS Score: {cvss_score}
Description: {description}

Respond ONLY in this exact format, nothing else:
SUMMARY: <your summary here>
RECOMMENDATION: <your recommendation here>
"""

    try:
        response = client.chat.completions.create(
            model="openai/gpt-oss-20b",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500,
            temperature=0.3,
        )

        content = response.choices[0].message.content

        summary = ""
        recommendation = ""

        if "SUMMARY:" in content and "RECOMMENDATION:" in content:
            parts = content.split("RECOMMENDATION:")
            summary = parts[0].replace("SUMMARY:", "").strip()
            recommendation = parts[1].strip()
        else:
            summary = content.strip()

        return summary, recommendation

    except Exception as e:
        return f"Error generating summary: {e}", ""