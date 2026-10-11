"""Build an offline review artifact from the design study; no source ingestion."""
import base64
from pathlib import Path
import argparse

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("output", type=Path)
args = parser.parse_args()
here = Path(__file__).resolve().parent
fonts = here.parents[2] / "clusterd/assets/fonts"
html = (here / "index.html").read_text()
html = html.replace("../../../clusterd/assets/fonts/space-grotesk-latin.woff2",
                    "data:font/woff2;base64," + base64.b64encode((fonts / "space-grotesk-latin.woff2").read_bytes()).decode())
license_text = (fonts / "OFL.txt").read_text()
spatial_markup, spatial_script = (here / "spatial.html").read_text().split("<script>", 1)
html = html.replace("<!-- SPATIAL_PROBE -->", spatial_markup)
link_markup, link_script = (here / "links.html").read_text().split("<script>", 1)
html = html.replace("<!-- LINK_EDITOR -->", link_markup)
html = html.replace("</body>", "<script>" + link_script + "<script>" + spatial_script + "\n</body>")
html = html.replace("<!-- FONT_LICENSE -->", "<!-- Embedded Space Grotesk, SIL OFL 1.1.\n" + license_text + "\n-->")
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(html)
print(args.output)
