const state = {
    mode: "url",
    samples: {},
    gaugeValue: 0,
};

const dom = {
    tabs: Array.from(document.querySelectorAll(".mode-pill")),
    urlEditor: document.getElementById("url-editor"),
    emailEditor: document.getElementById("email-editor"),
    urlInput: document.getElementById("url-input"),
    emailInput: document.getElementById("email-input"),
    analyzeBtn: document.getElementById("analyze-btn"),
    loading: document.getElementById("loading"),
    sampleTiles: Array.from(document.querySelectorAll(".sample-tile")),
    analysisMeta: document.getElementById("analysis-meta"),
    scoreValue: document.getElementById("score-value"),
    dialProgress: document.getElementById("dial-progress"),
    verdictBadge: document.getElementById("verdict-badge"),
    mlConfidence: document.getElementById("ml-confidence"),
    heuristicScoreText: document.getElementById("heuristic-score-text"),
    mlScoreText: document.getElementById("ml-score-text"),
    heuristicBar: document.getElementById("heuristic-bar"),
    mlBar: document.getElementById("ml-bar"),
    resultsSection: document.getElementById("results-section"),
    checksSummary: document.getElementById("checks-summary"),
    checksList: document.getElementById("checks-list"),
    mlPrediction: document.getElementById("ml-prediction"),
    mlNote: document.getElementById("ml-note"),
};

const dialRadius = Number(dom.dialProgress.getAttribute("r"));
const dialCircumference = 2 * Math.PI * dialRadius;
dom.dialProgress.style.strokeDasharray = String(dialCircumference);
dom.dialProgress.style.strokeDashoffset = String(dialCircumference);

function initialize() {
    dom.tabs.forEach((tab) => {
        tab.addEventListener("click", () => setMode(tab.dataset.mode));
    });

    dom.sampleTiles.forEach((tile) => {
        tile.addEventListener("click", () => applySample(tile.dataset.sample));
    });

    dom.analyzeBtn.addEventListener("click", analyzeCurrentInput);

    setMode("url");
    loadSamples();
}

function setMode(nextMode) {
    state.mode = nextMode === "email" ? "email" : "url";

    dom.tabs.forEach((tab) => {
        const active = tab.dataset.mode === state.mode;
        tab.classList.toggle("active", active);
        tab.setAttribute("aria-selected", String(active));
    });

    dom.urlEditor.classList.toggle("hidden", state.mode !== "url");
    dom.emailEditor.classList.toggle("hidden", state.mode !== "email");
}

async function loadSamples() {
    try {
        const response = await fetch("/api/samples");
        if (!response.ok) {
            return;
        }
        state.samples = await response.json();
    } catch (error) {
        console.error("Unable to fetch samples", error);
    }
}

async function applySample(sampleKey) {
    const sample = state.samples[sampleKey];
    if (!sample) {
        return;
    }

    if (sampleKey.includes("email")) {
        setMode("email");
        dom.emailInput.value = sample;
    } else {
        setMode("url");
        dom.urlInput.value = sample;
    }

    await analyzeCurrentInput();
}

async function analyzeCurrentInput() {
    const content = state.mode === "url" ? dom.urlInput.value.trim() : dom.emailInput.value.trim();

    if (!content) {
        const target = state.mode === "url" ? dom.urlInput : dom.emailInput;
        target.focus();
        target.style.borderColor = "#ff3b3b";
        setTimeout(() => {
            target.style.borderColor = "";
        }, 600);
        return;
    }

    setLoading(true);

    try {
        const response = await fetch("/api/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                type: state.mode,
                content,
            }),
        });

        const payload = await response.json();
        if (!response.ok) {
            throw new Error(payload.error || "Analysis failed");
        }

        renderResults(payload);
    } catch (error) {
        window.alert(`Analysis error: ${error.message}`);
    } finally {
        setLoading(false);
    }
}

function setLoading(isLoading) {
    dom.loading.classList.toggle("hidden", !isLoading);
    dom.analyzeBtn.disabled = isLoading;
    dom.analyzeBtn.style.opacity = isLoading ? "0.7" : "1";
}

function renderResults(payload) {
    const finalScore = Number(payload.score.final_score || 0);
    const heuristicScore = Number(payload.score.heuristic_score || 0);
    const mlScore = Number(payload.score.ml_score || 0);
    const threatLevel = String(payload.score.threat_level || "SAFE").toUpperCase();

    animateDial(finalScore);
    updateVerdictBadge(threatLevel);

    dom.mlConfidence.textContent = `ML confidence: ${mlScore.toFixed(1)}% phishing likelihood`;
    dom.heuristicScoreText.textContent = `${heuristicScore.toFixed(1)}/100`;
    dom.mlScoreText.textContent = `${mlScore.toFixed(1)}/100`;
    dom.heuristicBar.style.width = `${clamp(heuristicScore)}%`;
    dom.mlBar.style.width = `${clamp(mlScore)}%`;

    renderFeed(payload.heuristic.checks || [], payload.type);
    renderMLCard(payload.ml || {});

    const processedAt = payload.meta && payload.meta.processed_at ? formatTime(payload.meta.processed_at) : "just now";
    dom.analysisMeta.textContent = `Last scan: ${processedAt} • mode: ${payload.type.toUpperCase()}`;

    dom.resultsSection.classList.remove("hidden");
    requestAnimationFrame(() => dom.resultsSection.classList.add("visible"));
    dom.resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

function animateDial(targetScore) {
    const startScore = state.gaugeValue;
    const startAt = performance.now();
    const duration = 1100;

    function frame(now) {
        const progress = clamp01((now - startAt) / duration);
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = startScore + (targetScore - startScore) * eased;

        drawDial(current);
        dom.scoreValue.textContent = Math.round(current);

        if (progress < 1) {
            requestAnimationFrame(frame);
            return;
        }

        state.gaugeValue = targetScore;
    }

    requestAnimationFrame(frame);
}

function drawDial(score) {
    const bounded = clamp(score);
    const offset = dialCircumference * (1 - bounded / 100);

    dom.dialProgress.style.strokeDashoffset = String(offset);
    dom.dialProgress.style.stroke = scoreColor(bounded);
}

function updateVerdictBadge(level) {
    dom.verdictBadge.textContent = level;
    dom.verdictBadge.classList.remove("safe", "suspicious", "phishing");

    if (level === "SAFE") {
        dom.verdictBadge.classList.add("safe");
        return;
    }
    if (level === "SUSPICIOUS") {
        dom.verdictBadge.classList.add("suspicious");
        return;
    }
    dom.verdictBadge.classList.add("phishing");
}

function renderFeed(checks, type) {
    dom.checksSummary.textContent = `${String(type || "input").toUpperCase()} heuristic signals`;
    dom.checksList.innerHTML = "";

    checks.forEach((check, index) => {
        const item = document.createElement("li");
        const passed = Boolean(check.passed);
        item.className = `feed-item ${passed ? "pass" : "fail"}`;

        const statusText = passed ? "PASS" : "FAIL";
        const scoreText = `+${Number(check.score || 0)} pts`;

        item.innerHTML = `
            <div class="feed-title">
                <span>${escapeHtml(check.name || "Unnamed Check")}</span>
                <span class="feed-status ${passed ? "pass" : "fail"}">${statusText} • ${scoreText}</span>
            </div>
            <div class="feed-detail">${escapeHtml(check.detail || "No detail provided")}</div>
        `;

        dom.checksList.appendChild(item);
        setTimeout(() => item.classList.add("show"), 65 * index);
    });
}

function renderMLCard(ml) {
    const prediction = String(ml.prediction || "unknown").toUpperCase();
    const modelName = String(ml.model_name || "UnknownModel");
    const samples = ml.training_samples || "N/A";

    dom.mlPrediction.textContent = `Prediction: ${prediction}`;
    dom.mlNote.textContent = `Model: ${modelName} (TF-IDF), trained on ${samples} samples.`;
}

function scoreColor(score) {
    if (score <= 30) {
        return "#00e676";
    }
    if (score <= 50) {
        return "#f4cd4f";
    }
    if (score <= 70) {
        return "#ff9f43";
    }
    return "#ff3b3b";
}

function formatTime(isoText) {
    const parsed = new Date(isoText);
    if (Number.isNaN(parsed.getTime())) {
        return "just now";
    }
    return parsed.toLocaleString();
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function clamp(value) {
    return Math.max(0, Math.min(100, Number(value) || 0));
}

function clamp01(value) {
    return Math.max(0, Math.min(1, value));
}

initialize();
