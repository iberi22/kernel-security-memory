/**
 * Deterministic circular layout SVG neighbour graph.
 * Pure DOM SVG creation with no external physics library.
 */

const SVG_NS = 'http://www.w3.org/2000/svg';

export function renderNeighbourGraph(container, centerNode, relatedNodes, onSelect) {
  while (container.firstChild) {
    container.removeChild(container.firstChild);
  }

  if (!relatedNodes || relatedNodes.length === 0) {
    const empty = document.createElement('div');
    empty.style.padding = '16px';
    empty.style.color = 'var(--text-subtle)';
    empty.style.fontSize = '0.875rem';
    empty.textContent = 'No related vulnerabilities connected to this CVE.';
    container.appendChild(empty);
    return;
  }

  const width = 440;
  const height = 440;
  const cx = width / 2;
  const cy = height / 2;
  const radius = 145;

  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('class', 'graph-svg');
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', `Relationship graph for ${centerNode.id}`);

  const edgesGroup = document.createElementNS(SVG_NS, 'g');
  const nodesGroup = document.createElementNS(SVG_NS, 'g');

  const count = relatedNodes.length;
  const angleStep = (2 * Math.PI) / count;

  relatedNodes.forEach((node, i) => {
    const angle = i * angleStep - Math.PI / 2;
    const nx = cx + radius * Math.cos(angle);
    const ny = cy + radius * Math.sin(angle);

    // Edge Line
    const line = document.createElementNS(SVG_NS, 'line');
    line.setAttribute('x1', String(cx));
    line.setAttribute('y1', String(cy));
    line.setAttribute('x2', String(nx));
    line.setAttribute('y2', String(ny));
    line.setAttribute('class', 'graph-edge');

    const score = typeof node.score === 'number' ? node.score : 0.5;
    const strokeWidth = Math.max(1.5, Math.min(5, score * 5));
    line.setAttribute('stroke-width', String(strokeWidth));
    line.setAttribute('opacity', '0.6');
    edgesGroup.appendChild(line);

    // Edge score label
    const mx = (cx + nx) / 2;
    const my = (cy + ny) / 2;
    const edgeText = document.createElementNS(SVG_NS, 'text');
    edgeText.setAttribute('x', String(mx));
    edgeText.setAttribute('y', String(my - 4));
    edgeText.setAttribute('font-size', '10');
    edgeText.setAttribute('text-anchor', 'middle');
    edgeText.setAttribute('fill', 'var(--text-subtle)');
    edgeText.setAttribute('font-family', 'var(--font-mono)');
    edgeText.textContent = score.toFixed(2);
    edgesGroup.appendChild(edgeText);

    // Node Group
    const g = document.createElementNS(SVG_NS, 'g');
    g.setAttribute('class', 'graph-node');
    g.setAttribute('tabindex', '0');
    g.setAttribute('role', 'button');
    g.setAttribute('aria-label', `View related CVE ${node.id} in ${node.project}`);

    const circle = document.createElementNS(SVG_NS, 'circle');
    circle.setAttribute('cx', String(nx));
    circle.setAttribute('cy', String(ny));
    circle.setAttribute('r', '32');
    g.appendChild(circle);

    const titleText = document.createElementNS(SVG_NS, 'text');
    titleText.setAttribute('x', String(nx));
    titleText.setAttribute('y', String(ny - 4));
    titleText.setAttribute('font-size', '10');
    titleText.setAttribute('font-weight', '600');
    titleText.textContent = node.id;
    g.appendChild(titleText);

    const projText = document.createElementNS(SVG_NS, 'text');
    projText.setAttribute('x', String(nx));
    projText.setAttribute('y', String(ny + 10));
    projText.setAttribute('font-size', '9');
    projText.setAttribute('fill', 'var(--text-subtle)');
    projText.textContent = node.project || '';
    g.appendChild(projText);

    const navigate = () => {
      if (onSelect) {
        onSelect(node.project, node.id);
      }
    };

    g.addEventListener('click', navigate);
    g.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        navigate();
      }
    });

    nodesGroup.appendChild(g);
  });

  // Center Node
  const centerG = document.createElementNS(SVG_NS, 'g');
  centerG.setAttribute('class', 'graph-node center-node');

  const centerCircle = document.createElementNS(SVG_NS, 'circle');
  centerCircle.setAttribute('cx', String(cx));
  centerCircle.setAttribute('cy', String(cy));
  centerCircle.setAttribute('r', '38');
  centerG.appendChild(centerCircle);

  const centerIdText = document.createElementNS(SVG_NS, 'text');
  centerIdText.setAttribute('x', String(cx));
  centerIdText.setAttribute('y', String(cy - 4));
  centerIdText.setAttribute('font-size', '11');
  centerIdText.textContent = centerNode.id;
  centerG.appendChild(centerIdText);

  const centerProText = document.createElementNS(SVG_NS, 'text');
  centerProText.setAttribute('x', String(cx));
  centerProText.setAttribute('y', String(cy + 12));
  centerProText.setAttribute('font-size', '9');
  centerProText.textContent = centerNode.project || '';
  centerG.appendChild(centerProText);

  nodesGroup.appendChild(centerG);

  svg.appendChild(edgesGroup);
  svg.appendChild(nodesGroup);
  container.appendChild(svg);
}
