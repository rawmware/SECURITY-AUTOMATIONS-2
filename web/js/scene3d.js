/* AegisScene — 3D ops constellation (Three.js).
 * Central core + six satellite nodes (web, api, db, auth, mail, edge),
 * ambient threat particles, attack streams, shield intercepts.
 * Usage: const scene = window.AegisScene(document.getElementById('scene')); */
import * as THREE from "three";

window.AegisScene = (function () {
  "use strict";

  const AMBER = 0xe8a33d;
  const RED = 0xe5484d;
  const GREEN = 0x46a758;
  const PAPER = 0xedeae3;

  const NODES = [
    { id: "web", label: "WEB", pos: [2.7, 0.7, 0.2] },
    { id: "api", label: "API", pos: [-2.7, 0.9, 0.5] },
    { id: "db", label: "DB", pos: [1.5, -1.7, -1.1] },
    { id: "auth", label: "AUTH", pos: [-1.7, -1.5, 1.0] },
    { id: "mail", label: "MAIL", pos: [0.5, 1.9, -1.4] },
    { id: "edge", label: "EDGE", pos: [-0.7, 0.3, 2.5] },
  ];

  function makeLabel(text) {
    const c = document.createElement("canvas");
    c.width = 256;
    c.height = 64;
    const g = c.getContext("2d");
    g.font = "600 26px 'JetBrains Mono', monospace";
    g.textAlign = "center";
    g.textBaseline = "middle";
    g.fillStyle = "rgba(237,234,227,0.85)";
    g.fillText(text, 128, 34);
    const tex = new THREE.CanvasTexture(c);
    tex.anisotropy = 4;
    const mat = new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false });
    const sp = new THREE.Sprite(mat);
    sp.scale.set(1.15, 0.29, 1);
    return sp;
  }

  function init(canvas) {
    const small = Math.min(window.innerWidth, window.innerHeight) < 700;
    const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, small ? 1.5 : 2));

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(46, 1, 0.1, 100);
    camera.position.set(0, 1.4, 7.6);
    camera.lookAt(0, 0, 0);

    const root = new THREE.Group();
    scene.add(root);

    /* central core: wireframe icosahedron */
    const core = new THREE.Mesh(
      new THREE.IcosahedronGeometry(1.05, 1),
      new THREE.MeshBasicMaterial({ color: AMBER, wireframe: true, transparent: true, opacity: 0.85 })
    );
    root.add(core);
    const coreInner = new THREE.Mesh(
      new THREE.IcosahedronGeometry(0.55, 0),
      new THREE.MeshBasicMaterial({ color: AMBER, wireframe: true, transparent: true, opacity: 0.35 })
    );
    root.add(coreInner);

    /* satellite nodes */
    const nodeObjs = {};
    const lineMat = new THREE.LineBasicMaterial({ color: PAPER, transparent: true, opacity: 0.16 });
    NODES.forEach((n) => {
      const grp = new THREE.Group();
      grp.position.set(...n.pos);
      const halo = new THREE.Mesh(
        new THREE.SphereGeometry(0.3, 20, 14),
        new THREE.MeshBasicMaterial({ color: PAPER, transparent: true, opacity: 0.9 })
      );
      const ring = new THREE.Mesh(
        new THREE.RingGeometry(0.42, 0.46, 48),
        new THREE.MeshBasicMaterial({ color: PAPER, transparent: true, opacity: 0.35, side: THREE.DoubleSide })
      );
      const label = makeLabel(n.label);
      label.position.y = 0.62;
      grp.add(halo, ring, label);
      root.add(grp);
      const geo = new THREE.BufferGeometry().setFromPoints([
        new THREE.Vector3(0, 0, 0),
        new THREE.Vector3(...n.pos),
      ]);
      root.add(new THREE.Line(geo, lineMat));
      nodeObjs[n.id] = { grp, halo, ring, flash: 0, baseColor: PAPER };
    });

    /* ambient drifting threat particles */
    const P_COUNT = small ? 120 : 320;
    const pGeo = new THREE.BufferGeometry();
    const pPos = new Float32Array(P_COUNT * 3);
    const pVel = new Float32Array(P_COUNT * 3);
    for (let i = 0; i < P_COUNT; i++) {
      pPos[i * 3] = (Math.random() - 0.5) * 12;
      pPos[i * 3 + 1] = (Math.random() - 0.5) * 8;
      pPos[i * 3 + 2] = (Math.random() - 0.5) * 10;
      pVel[i * 3] = (Math.random() - 0.5) * 0.15;
      pVel[i * 3 + 1] = (Math.random() - 0.5) * 0.1;
      pVel[i * 3 + 2] = (Math.random() - 0.5) * 0.15;
    }
    pGeo.setAttribute("position", new THREE.BufferAttribute(pPos, 3));
    const particles = new THREE.Points(
      pGeo,
      new THREE.PointsMaterial({ color: 0x8a8f98, size: 0.035, transparent: true, opacity: 0.55 })
    );
    root.add(particles);

    /* attack streams + shield rings (pooled) */
    const streams = [];
    const rings = [];
    const tmpV = new THREE.Vector3();

    function spawnStream(targetId, kind) {
      const node = nodeObjs[targetId] || nodeObjs.edge;
      const target = node.grp.position.clone();
      const n = kind === "breach" ? 26 : kind === "exfil" ? 20 : 12;
      const color = kind === "probe" ? 0x8a8f98 : RED;
      for (let i = 0; i < n; i++) {
        const start = target
          .clone()
          .add(new THREE.Vector3((Math.random() - 0.5) * 9, (Math.random() - 0.5) * 6 + 2, (Math.random() - 0.5) * 8 - 2));
        const m = new THREE.Mesh(
          new THREE.SphereGeometry(kind === "probe" ? 0.03 : 0.045, 8, 6),
          new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.95 })
        );
        m.position.copy(start);
        root.add(m);
        streams.push({
          mesh: m,
          from: start,
          to: target,
          t: Math.random() * 0.25,
          speed: 0.55 + Math.random() * 0.5,
        });
      }
      node.flash = 1;
    }

    function spawnRing(targetId, color) {
      const node = nodeObjs[targetId] || nodeObjs.edge;
      const ring = new THREE.Mesh(
        new THREE.RingGeometry(0.5, 0.56, 64),
        new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.9, side: THREE.DoubleSide })
      );
      ring.position.copy(node.grp.position);
      ring.lookAt(camera.position);
      root.add(ring);
      rings.push({ mesh: ring, t: 0 });
    }

    let threatLevel = 0.15;
    let running = true;
    let last = performance.now();

    function tick(now) {
      if (!running) return;
      requestAnimationFrame(tick);
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;

      /* slow rotation */
      root.rotation.y += dt * 0.08;
      core.rotation.x += dt * 0.25;
      coreInner.rotation.y -= dt * 0.4;

      /* ambient particles drift; speed scales with threat level */
      const arr = pGeo.attributes.position.array;
      const boost = 1 + threatLevel * 2.5;
      for (let i = 0; i < P_COUNT; i++) {
        arr[i * 3] += pVel[i * 3] * boost * dt * 8;
        arr[i * 3 + 1] += pVel[i * 3 + 1] * boost * dt * 8;
        arr[i * 3 + 2] += pVel[i * 3 + 2] * boost * dt * 8;
        for (let a = 0; a < 3; a++) {
          const lim = a === 1 ? 4.5 : 6.5;
          if (arr[i * 3 + a] > lim) arr[i * 3 + a] = -lim;
          if (arr[i * 3 + a] < -lim) arr[i * 3 + a] = lim;
        }
      }
      pGeo.attributes.position.needsUpdate = true;
      particles.material.opacity = 0.35 + threatLevel * 0.4;

      /* attack streams fly toward their node */
      for (let i = streams.length - 1; i >= 0; i--) {
        const s = streams[i];
        s.t += dt * s.speed;
        if (s.t >= 1) {
          root.remove(s.mesh);
          s.mesh.geometry.dispose();
          s.mesh.material.dispose();
          streams.splice(i, 1);
          continue;
        }
        s.mesh.position.lerpVectors(s.from, s.to, s.t * s.t);
        s.mesh.material.opacity = 0.95 * (1 - s.t * 0.4);
      }

      /* shield rings expand and fade */
      for (let i = rings.length - 1; i >= 0; i--) {
        const r = rings[i];
        r.t += dt * 1.4;
        if (r.t >= 1) {
          root.remove(r.mesh);
          r.mesh.geometry.dispose();
          r.mesh.material.dispose();
          rings.splice(i, 1);
          continue;
        }
        const s = 1 + r.t * 3.2;
        r.mesh.scale.set(s, s, 1);
        r.mesh.material.opacity = 0.9 * (1 - r.t);
      }

      /* node flash decay */
      for (const id of Object.keys(nodeObjs)) {
        const n = nodeObjs[id];
        if (n.flash > 0) {
          n.flash = Math.max(0, n.flash - dt * 1.6);
          n.halo.material.color.setHex(RED).lerp(new THREE.Color(PAPER), 1 - n.flash);
          const pulse = 1 + n.flash * 0.7;
          n.halo.scale.set(pulse, pulse, pulse);
        }
      }

      /* core warms with threat level */
      core.material.opacity = 0.6 + threatLevel * 0.4;

      renderer.render(scene, camera);
    }

    function resize() {
      const w = canvas.clientWidth || canvas.parentElement.clientWidth || 300;
      const h = canvas.clientHeight || 420;
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
    }

    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        running = false;
      } else {
        running = true;
        last = performance.now();
        requestAnimationFrame(tick);
      }
    });
    window.addEventListener("resize", resize);
    resize();
    requestAnimationFrame(tick);

    return {
      attack(nodeId, kind) {
        spawnStream(nodeId, kind || "probe");
        threatLevel = Math.min(1, threatLevel + (kind === "probe" ? 0.06 : 0.14));
      },
      shield(nodeId) {
        spawnRing(nodeId, AMBER);
      },
      pulse(nodeId, color) {
        const n = nodeObjs[nodeId];
        if (n) {
          n.flash = 1;
          n.halo.material.color.setHex(color === "green" ? GREEN : AMBER);
        }
      },
      setThreatLevel(v) {
        threatLevel = Math.max(0, Math.min(1, v));
      },
      decayThreat() {
        threatLevel = Math.max(0.12, threatLevel * 0.94);
      },
      resize,
      nodeIds: NODES.map((n) => n.id),
    };
  }

  return init;
})();
