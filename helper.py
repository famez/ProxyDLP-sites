import json
import base64

#Helper functions

def pad_b64(segment: str) -> str:
    return segment + '=' * (-len(segment) % 4)

def decode_jwt(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(base64.urlsafe_b64decode(pad_b64(parts[0])).decode())
        payload = json.loads(base64.urlsafe_b64decode(pad_b64(parts[1])).decode())
        return {"header": header, "payload": payload}
    except Exception as e:
        ctx.log.warn(f"JWT decoding error: {str(e)}")
        return None


def extract_substring_between(s, start, end):
    
    # Find the index of the start substring
    idx1 = s.find(start)

    # Find the index of the end substring, starting after the start substring
    idx2 = s.find(end, idx1 + len(start))

    # Check if both delimiters are found and extract the substring between them
    if idx1 != -1 and idx2 != -1:
        res = s[idx1 + len(start):idx2]
        return res  # Output: world
    
    return ""