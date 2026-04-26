import easyocr
import sys
import json
import os

def run_easyocr(image_path):
    # Initialize reader (first run will download models)
    # EasyOCR automatically detects MPS/GPU on Mac
    reader = easyocr.Reader(['en'], gpu=True)
    result = reader.readtext(image_path)
    
    output = []
    for (bbox, text, prob) in result:
        # bbox: [[x0,y0], [x1,y1], [x2,y2], [x3,y3]]
        x_coords = [p[0] for p in bbox]
        y_coords = [p[1] for p in bbox]
        x_min, y_min = int(min(x_coords)), int(min(y_coords))
        x_max, y_max = int(max(x_coords)), int(max(y_coords))
        
        output.append({
            "text": text,
            "conf": round(float(prob) * 100, 1),
            "bbox": {
                "x": x_min,
                "y": y_min,
                "w": x_max - x_min,
                "h": y_max - y_min
            }
        })
    return output

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
        
    img_path = sys.argv[1]
    if not os.path.exists(img_path):
        sys.exit(1)

    try:
        results = run_easyocr(img_path)
        print(json.dumps(results))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
