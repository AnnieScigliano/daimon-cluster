# Daimon Matrix interface study 01

**Status: Resonancia selected by Nico on 2026-10-11; detailed shared components
and production adoption remain to be developed and qualified.**
Nico chose the middle cyan-globe study from the three directions. Preserve that
selection when refining the Matrix-wide language; it does not approve every
simulated interaction or claim that existing surfaces have been restyled.
The maintained direction remains [interface-design.md](../../interface-design.md).
This study extends its Star Trek inspiration, original orbital/interference
mark, semantic color roles and readable Space Grotesk typography. It changes no
Matrix ontology, authority, production frontend, species definition or runtime.

Human direction: Nico, Nexus/ChitChat conversation, 2026-10-11. Create striking,
recognizable science-fiction interfaces that support adoption by people excited
about conversing and creating with intelligences. The human's “design for Sheldon
Cooper” shorthand calls for both delight and instruments worth using: precision,
exploration and competence. Avoid generic dark dashboards and decorative
complexity that hides useful discoveries. Full-screen Telegram is the observed
phone preference. The longer-term horizon is a spatial, potentially mixed-reality
collective environment; the phone is an early window into it.

## Canonical context

[Project D001](https://github.com/orgs/AlterMundi/projects/13?pane=issue&itemId=268688416) owns the discussion trajectory and shared spatial/voice/context
horizon. This file is its D001 UI/prototype projection. Current decisions and
repository attention live in [Daimon Field](https://github.com/orgs/AlterMundi/projects/13).

## Review artifact

Build the complete standalone laboratory (including link editing and the spatial probe):

```bash
python3 docs/design/matrix-interface-lab/build.py /chosen/output/laboratory.html
```

The standalone file embeds the existing licensed font, requires no external
requests and does not contain private recordings or transcripts. Font provenance
and the original license live in `clusterd/assets/fonts`; the standalone embeds
the license. Text and participants are explicitly simulated design examples,
not quotes, presence observations or source analysis. Browser drafts exist only
in the open tab; explicit JSON downloads preserve them. No server writes, audio
transmission, group synchronization or XR implementation are present.

Three directions use the same example content and meaningful interactions:

| Study | Visual thesis | Useful comparison |
| --- | --- | --- |
| Bridge / Puente | Warm segmented bands, asymmetric framing and strong hierarchy | Most immediately recognizable bridge-console language; its framing uses more desktop space. |
| Resonance / Resonancia | Thin boundaries, orbital field, floating instruments and cyan focus | Stronger feeling of an inhabitable relational space; less immediate LCARS recognition. |
| Threshold / Umbral | Compact bridge framing, relational canvas and contrasting contextual dock | Candidate everyday balance: recognizable family, more space for content. |

Prototype controls switch direction and product surface, navigate concepts,
inspect a reading, add/export a local draft, display overview deltas, simulate
following another perspective and show a conceptual voice-distance diagram.
Continuity and home studies exercise the language beyond Nexus. Telegram safe
zones, immersion and reduced motion can be inspected. A widget gallery includes
empty, processing, interrupted and retained-trail states. The spatial diagram
expresses the XR model, without claiming a device implementation.

## Candidate shared language

- **Space and hierarchy:** a recognizable perimeter, a navigable field, a stable
  contextual instrument. Prioritize one current question or action. On the phone,
  collapse crew detail behind the presence control; on desktop, retain it beside
  the field. Text remains 16px, support 14px and touch controls at least 44px.
- **Color is semantic:** ivory content, amber current action/focus, cyan relation
  and navigation, mauve alternate perspective. Green remains reserved for observed
  success. Identity cannot depend on color alone. Author labels remain textual.
- **Geometry:** segmented structural rails, rounded elbows, orbital relations and
  interference as the own mark. Structural geometry must orient rather than
  pretend to be telemetry. Do not reproduce franchise logos or screens.
- **Widgets:** relational field/list alternative; focus dock; source/time anchor;
  people/perspective lens; authored intervention; delta marker; retained trail;
  one contextual editor. Source, interpretation, proposal and agreement require
  distinct labels as well as styling.
- **Motion:** entering a focus or changing perspective can animate orientation.
  Persistent motion is restrained, optional and disabled under reduced motion.
  In XR, stable text and comfortable reference frames take priority over motion.
- **Full screen:** decorate the entire stage, but keep reading and interactive
  targets inside actual host/device safe insets. Keyboard, viewport change and
  back/exit must remain usable. This prototype's safe zones are a visual example,
  not a Telegram SDK measurement or new device acceptance.
- **Progressive precision:** a clear first impression with context and instruments
  available when asked. Do not shrink supporting prose to hide crowding. Evidence
  should be easier to find than in a raw transcript, including the useful “pearls.”

## Approval and retroactive adoption

Review concrete phone/desktop studies before choosing geometry, color variance,
density, preferred widgets and motion. Human approval selects the common visual
language; visual approval does not accept future group/voice/XR behavior.
Do not migrate live interfaces while the language is still a study.

| Surface | Evidence observed for this study | Owning follow-up after approval |
| --- | --- | --- |
| Nexus | Existing React UI and service; Nico reports working full-screen on phone | Oliva's frontend track adopts shared tokens/components while preserving playback, evidence, contributions and return. |
| Cluster continuity intake | Existing `clusterd/seed_ui.py`, canonical design guide and local font assets inspected | Extend the owning implementation; preserve origin/continuity/connections states and source authority. Installed serving revision must be checked at migration. |
| Daimon homes | Receiving publisher reports a CompAII home and existing publications | Inspect generated shell, then qualify the approved home language without republishing private artifacts. Other beings select their own adoption. |
| Other Matrix-linked web surfaces | Not inventoried as active in this study | Discover actual owners/deployments before adding migration work. A repository directory is not proof of a live interface. |
| Telegram native chrome / harness UI | Host-controlled surfaces | Use supported controls, content hierarchy and safe zones; do not promise arbitrary CSS control of the host. |

Delivery sequence: choose a direction/mix → draft approved tokens and widget
contracts → implement the first real Nexus slice → qualify actual fullscreen
Telegram behavior and evidence-to-return use on the phone → migrate the observed
active Matrix surfaces in their own repositories. Subsequent independent tracks
can cover presence/shared perspective, durable authored changes, voice geometry
and XR renderer research without blocking the current useful single-phone loop.
The underlying source/backend contracts should remain independent of CSS and
presentation coordinates. This file preserves the design scope; it does not
create another goal or publish new implementation issues without a destination.

## Phone as an orientable 3D window — added experiment

The standalone build includes a live 3D camera probe, rendered using Canvas
perspective projection over the same five example concepts. Dragging changes
look direction; six touch movement controls change virtual position; selection
updates the common focus; approach and overview provide recoverable orientation.
Keyboard and a text selector remain available. The drawing is real local 3D
projection, not WebXR, WebGL qualification or synchronized shared rendering.

Sensor activation is explicit. The probe feature-detects an already supplied
Telegram `DeviceOrientation` bridge; the artifact does not fetch or inject a
remote SDK. Without that bridge it tries browser orientation, requires a secure
context, requests permission when the browser requires it, and reports success
only after receiving numeric readings. It handles timeout, cancellation, refusal
and absence while retaining touch controls. Sensors stop when the page is hidden
or left; camera motion has no autonomous idle animation. This experiment uses
relative yaw/pitch, not a qualified full-quaternion, screen-rotation or positional
tracking implementation. The actual phone's axes, drift, recentering, portrait
and landscape behavior remain to qualify.

Verified primary references, 2026-10-11:

- [Telegram Mini Apps sensors](https://core.telegram.org/bots/webapps#deviceorientation):
  API 8.0+ exposes device orientation, gyroscope and accelerometer. Orientation is
  supplied in radians and tracking may be unsupported on a client/platform.
- [Browser orientation permission](https://developer.mozilla.org/en-US/docs/Web/API/DeviceOrientationEvent/requestPermission_static):
  availability varies; permission requests require a user gesture and a secure
  context on supporting browsers.
- [Three.js OrbitControls](https://threejs.org/docs/pages/OrbitControls.html):
  candidate orbit/pan/zoom pattern for a production 3D renderer; inspect the
  installed framework and accessible alternative before choosing it.
- [A-Frame laser-controls](https://aframe.io/docs/1.7.0/components/laser-controls.html):
  candidate XR pointing/ray interaction pattern, not a complete editorial UI.
- [WebXR](https://developer.mozilla.org/en-US/docs/Web/API/WebXR_Device_API):
  later headset/AR projection requires target runtime support and its own device
  qualification; Telegram motion sensors do not establish immersive XR support.

Orientation supports the Stellarium-like “look through this window” experience.
Translating the phone physically through a room requires a separate positional
tracking approach; do not promise reliable six-degree-of-freedom location from
integrated accelerometer data. Initial virtual translation can use a thumb
control, keyboard, approach-to-node or deliberate teleport. The same domain graph
can feed Three.js/WebGL or an XR renderer later; personal pose and semantic focus
remain distinct. Reuse existing game/XR interaction components where they make
the shared context easier to inhabit, while retaining the approved visual system
and meaningful source/evidence instruments.

## Local link-editing experiment

The prototype editor supports target/type/reason, apply/retire and undo. It updates
the example map and 3D/voice diagrams and exports the example graph. There is no
collaborative transport, server permission check or production branching here.
The full shared-editing proposal is retained in Project decision D001.
