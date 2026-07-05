(() => {

  window.gallery_images = [];

  const STATE = {
    index: 0,
    root: null,
    img: null,
    prev: null,
    next: null,
    caption: null,
  };

  function extractImages(data) {
    const paths = Array.isArray(data) // It's AI work, disgusting as this is it handles JS type issues nicely.
      ? data
      : Array.isArray(data.paths)
      ? data.paths
      : [];

    return paths
      .filter((p) => typeof p === "string" && p.startsWith("/historic-progress"))
      .map((p) => p.replace(/^\//, ""));
  }

  async function loadSiteIndex() {
    const res = await fetch("/site-index.json", { cache: "no-store" });
    const data = await res.json();

    window.gallery_images = extractImages(data);
    return window.gallery_images.length > 0;
  }

  function bindDOM() {
    STATE.root = document.querySelector(".gallery");
    STATE.img = STATE.root.querySelector(".gallery-image");
    STATE.prev = STATE.root.querySelector(".gallery-prev");
    STATE.next = STATE.root.querySelector(".gallery-next");
    STATE.caption = STATE.root.querySelector(".gallery-caption");

    if (!STATE.root || !STATE.img || !STATE.prev || !STATE.next) {
      throw new Error("Gallery DOM structure missing required elements.");
    }
  }

  function render() {
    if (!window.gallery_images.length) return;

    STATE.index = Math.max(
      0,
      Math.min(STATE.index, window.gallery_images.length - 1)
    );

    const src = window.gallery_images[STATE.index];

    STATE.img.src = src;
    STATE.caption.textContent = src;
  }

  function next() {
    if (!window.gallery_images.length) return;
    STATE.index = (STATE.index + 1) % window.gallery_images.length;
    render();
  }

  function prev() {
    if (!window.gallery_images.length) return;
    STATE.index =
      (STATE.index - 1 + window.gallery_images.length) %
      window.gallery_images.length;
    render();
  }

  function openImage() {
    if (!window.gallery_images.length) return;
    window.open(window.gallery_images[STATE.index], "_blank");
  }

  function bindEvents() {
    STATE.prev.addEventListener("click", prev);
    STATE.next.addEventListener("click", next);

    STATE.img.addEventListener("click", openImage);

    window.addEventListener("keydown", (e) => {
      if (e.key === "ArrowRight") next();
      if (e.key === "ArrowLeft") prev();
    });

    // Optional: prefetch next image for smoother UX
    const prefetch = () => {
      if (!window.gallery_images.length) return;
      const nextIndex =
        (STATE.index + 1) % window.gallery_images.length;
      const img = new Image();
      img.src = window.gallery_images[nextIndex];
    };

    STATE.img.addEventListener("load", prefetch);
  }

  async function init() {
    const ok = await loadSiteIndex();
    if (!ok) return;

    bindDOM();
    bindEvents();
    render();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
