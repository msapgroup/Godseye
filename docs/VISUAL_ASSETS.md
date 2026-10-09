# Dashboard artwork

The original GODSEYE logo remains `app/assets/godseye-approved.png` and is unchanged.

Local assets under `app/assets/visual/` implement the approved preview. No third-party CDN is required for the dashboard. Realistic device atlases are displayed through native SVG viewports, with existing device icon keys and custom uploaded images preserved.

The device atlases were created and their backgrounds removed using the built-in image-generation tool. The prompt specified equal 4-by-2 cells, realistic product materials, consistent three-quarter perspective, cyan edge lighting, no labels or logos, and preservation of the entire device silhouette when making the background transparent. The three atlases cover core network appliances and computers, business/mobile devices, and home/security devices. The existing specialist vector icons remain available.

The Earth surface is NASA Earth Observatory's July 2004 Blue Marble Next Generation with Topography and Bathymetry, served locally as `earth-texture.jpg`. The image uses the geographic global projection required by the city-coordinate overlays. The cloud layer is illustrative artwork from the approved preview, not a live weather feed.

Credit: NASA Earth Observatory / Blue Marble Next Generation. [Source and global-image downloads](https://science.nasa.gov/earth/earth-observatory/blue-marble-next-generation/base-topography-bathymetry/). [NASA Earth imagery reuse guidance](https://science.nasa.gov/earth/faq/). This visualization does not imply NASA endorsement.

 Geographic preview pins use equirectangular latitude/longitude calculations; world pulse paths are labeled illustrative. Discovered network relationships continue to come from the existing topology API.

Linked Sites city thumbnails use the approved first dashboard preview, clipped by native SVG viewports to remove surrounding panel edges. They are artwork, not images supplied by the paired installation.
