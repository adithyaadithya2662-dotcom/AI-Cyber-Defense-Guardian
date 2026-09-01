// ============================================
// AI CYBER DEFENSE GUARDIAN
// FRONTEND APPLICATION
// ============================================

// Use the same server that is serving the dashboard.
const API_BASE = "";

// ============================================
// APPLICATION STATE
// ============================================

let events = [];
let riskHistory = [];

let riskChart = null;
let threatChart = null;


// ============================================
// DOM ELEMENTS
// ============================================

const totalEventsElement = document.getElementById("totalEvents");
const criticalThreatsElement = document.getElementById("criticalThreats");
const highThreatsElement = document.getElementById("highThreats");

const currentRiskElement = document.getElementById("currentRisk");
const riskScoreElement = document.getElementById("riskScore");
const riskSeverityElement = document.getElementById("riskSeverity");

const threatListElement = document.getElementById("threatList");
const aiAnalysisElement = document.getElementById("aiAnalysis");
const recommendationsElement = document.getElementById("recommendations");
const incidentTimelineElement = document.getElementById("incidentTimeline");

const scanButton = document.getElementById("scanButton");


// ============================================
// START APPLICATION
// ============================================

document.addEventListener("DOMContentLoaded", () => {

    initializeCharts();

    scanButton.addEventListener("click", runSecurityScan);

    updateDashboard();

});


// ============================================
// RUN SECURITY SCAN
// ============================================

async function runSecurityScan() {

    scanButton.disabled = true;
    scanButton.textContent = "SCANNING...";

    try {

        const response = await fetch(`${API_BASE}/api/analyze`, {
            method: "GET",
            headers: {
                "Accept": "application/json"
            },
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error(`API returned HTTP ${response.status}`);
        }

        const data = await response.json();

        console.log("Security scan result:", data);

        processSecurityEvent(data);

    } catch (error) {

        console.error("Security scan failed:", error);

        showError(
            "Unable to connect to the security analysis API. " +
            "Please check the deployment logs."
        );

    } finally {

        scanButton.disabled = false;
        scanButton.textContent = "RUN SECURITY SCAN";

    }
}


// ============================================
// PROCESS SECURITY EVENT
// ============================================

function processSecurityEvent(data) {

    if (!data || !data.event || !data.final_risk) {

        console.error("Invalid API response:", data);

        showError("Invalid security analysis response.");

        return;
    }


    // ========================================
    // IMPORTANT:
    // Use FINAL RISK severity.
    //
    // NOT rule_analysis.severity
    // ========================================

    const event = {
        ...data,

        id: Date.now(),

        timestamp: data.event.timestamp ||
                   new Date().toLocaleString(),

        finalScore: Number(
            data.final_risk.final_risk_score || 0
        ),

        finalSeverity: String(
            data.final_risk.severity || "LOW"
        ).toUpperCase(),

        threatType:
            data.explanation?.threat_type ||
            "Security Event",

        username:
            data.event.username ||
            "Unknown",

        ip:
            data.event.ip_address ||
            "Unknown",

        eventType:
            data.event.event_type ||
            "unknown"
    };


    // Add newest event to beginning.
    events.unshift(event);


    // Keep maximum 100 events in browser memory.
    if (events.length > 100) {
        events = events.slice(0, 100);
    }


    // Store risk history.
    riskHistory.push({
        label: getTimeLabel(),
        score: event.finalScore
    });


    if (riskHistory.length > 30) {
        riskHistory.shift();
    }


    updateDashboard();

    displayAIAnalysis(event);

    displayRecommendations(event);

    displayIncidentTimeline(event);

    updateCharts();

}


// ============================================
// UPDATE COMPLETE DASHBOARD
// ============================================

function updateDashboard() {

    updateStatistics();

    updateCurrentRisk();

    updateThreatList();

}


// ============================================
// UPDATE STATISTICS
// ============================================

function updateStatistics() {

    // TOTAL EVENTS

    totalEventsElement.textContent = events.length;


    // CRITICAL

    const criticalCount = events.filter(event => {

        return event.finalSeverity === "CRITICAL";

    }).length;


    criticalThreatsElement.textContent = criticalCount;


    // HIGH

    const highCount = events.filter(event => {

        return event.finalSeverity === "HIGH";

    }).length;


    highThreatsElement.textContent = highCount;


    console.log("Statistics:", {
        total: events.length,
        critical: criticalCount,
        high: highCount
    });

}


// ============================================
// UPDATE CURRENT RISK
// ============================================

function updateCurrentRisk() {

    if (events.length === 0) {

        currentRiskElement.textContent = "0";

        riskScoreElement.innerHTML =
            `0 <small>/100</small>`;

        riskSeverityElement.textContent = "LOW";

        return;
    }


    const latestEvent = events[0];

    const score = latestEvent.finalScore;

    const severity = latestEvent.finalSeverity;


    currentRiskElement.textContent = score;

    riskScoreElement.innerHTML =
        `${score} <small>/100</small>`;

    riskSeverityElement.textContent = severity;


    updateRiskAppearance(severity);

}


// ============================================
// RISK APPEARANCE
// ============================================

function updateRiskAppearance(severity) {

    const riskCircle = document.querySelector(".risk-circle");

    if (!riskCircle) {
        return;
    }


    // Remove previous classes.

    riskCircle.classList.remove(
        "risk-low",
        "risk-medium",
        "risk-high",
        "risk-critical"
    );


    switch (severity) {

        case "CRITICAL":

            riskCircle.classList.add("risk-critical");

            break;


        case "HIGH":

            riskCircle.classList.add("risk-high");

            break;


        case "MEDIUM":

            riskCircle.classList.add("risk-medium");

            break;


        default:

            riskCircle.classList.add("risk-low");

            break;
    }

}


// ============================================
// THREAT LIST
// ============================================

function updateThreatList() {

    if (events.length === 0) {

        threatListElement.innerHTML = `
            <div class="empty-state">

                No security events detected yet.

                <br><br>

                Click
                <strong>RUN SECURITY SCAN</strong>
                to begin analysis.

            </div>
        `;

        return;
    }


    threatListElement.innerHTML = events
        .slice(0, 20)
        .map(event => {

            const severityClass =
                event.finalSeverity.toLowerCase();


            const score = event.finalScore;


            return `

                <div class="threat-item ${severityClass}">

                    <div class="threat-indicator"></div>

                    <div class="threat-content">

                        <h3>
                            ${escapeHTML(event.threatType)}
                        </h3>

                        <p>
                            User:
                            <strong>
                                ${escapeHTML(event.username)}
                            </strong>

                            &nbsp; • &nbsp;

                            IP:
                            ${escapeHTML(event.ip)}
                        </p>

                        <p>
                            Event:
                            ${escapeHTML(event.eventType)}
                        </p>

                    </div>

                    <div class="threat-score">

                        <strong>
                            ${score}/100
                        </strong>

                        <span>
                            ${event.finalSeverity}
                        </span>

                    </div>

                </div>

            `;

        })
        .join("");

}


// ============================================
// AI ANALYSIS
// ============================================

function displayAIAnalysis(event) {

    const ai = event.ai_analysis;
    const explanation = event.explanation;
    const finalRisk = event.final_risk;


    if (!ai || !explanation) {
        return;
    }


    const reasons =
        explanation.reasons || [];


    aiAnalysisElement.innerHTML = `

        <div class="analysis-card">

            <div class="analysis-header">

                <h3>
                    ${escapeHTML(
                        explanation.threat_type ||
                        "Security Threat"
                    )}
                </h3>

                <span class="severity-badge ${event.finalSeverity.toLowerCase()}">
                    ${event.finalSeverity}
                </span>

            </div>


            <div class="analysis-details">

                <div>
                    <strong>Risk Score</strong>
                    <span>
                        ${event.finalScore}/100
                    </span>
                </div>


                <div>
                    <strong>Rule Risk</strong>
                    <span>
                        ${event.rule_analysis?.risk_score ?? 0}/100
                    </span>
                </div>


                <div>
                    <strong>AI Anomaly Score</strong>
                    <span>
                        ${ai.anomaly_score ?? 0}
                    </span>
                </div>


                <div>
                    <strong>AI Anomaly</strong>
                    <span>
                        ${ai.is_anomaly ? "YES" : "NO"}
                    </span>
                </div>


                <div>
                    <strong>Confidence</strong>
                    <span>
                        ${explanation.confidence ?? 0}%
                    </span>
                </div>

            </div>


            <h4>
                Detection Reasons
            </h4>


            <ul>

                ${reasons.map(reason => `
                    <li>
                        ${escapeHTML(reason)}
                    </li>
                `).join("")}

            </ul>

        </div>

    `;

}


// ============================================
// RECOMMENDATIONS
// ============================================

function displayRecommendations(event) {

    const recommendations =
        event.explanation?.recommendations || [];


    if (recommendations.length === 0) {

        recommendationsElement.innerHTML = `
            <div class="empty-state">
                No recommendations available.
            </div>
        `;

        return;
    }


    recommendationsElement.innerHTML = `

        <div class="recommendation-list">

            ${recommendations.map((recommendation, index) => `

                <div class="recommendation-item">

                    <span class="recommendation-number">
                        ${index + 1}
                    </span>

                    <span>
                        ${escapeHTML(recommendation)}
                    </span>

                </div>

            `).join("")}

        </div>

    `;

}


// ============================================
// INCIDENT TIMELINE
// ============================================

function displayIncidentTimeline(event) {

    if (!event) {
        return;
    }


    const existing =
        incidentTimelineElement.innerHTML;


    const isEmpty =
        existing.includes("No incidents recorded yet.");


    const newIncident = `

        <div class="timeline-item ${event.finalSeverity.toLowerCase()}">

            <div class="timeline-marker"></div>

            <div class="timeline-content">

                <div class="timeline-time">
                    ${escapeHTML(event.timestamp)}
                </div>

                <h3>
                    ${escapeHTML(event.threatType)}
                </h3>

                <p>
                    ${escapeHTML(event.eventType)}
                    • User:
                    ${escapeHTML(event.username)}
                    • IP:
                    ${escapeHTML(event.ip)}
                </p>

                <strong>
                    Risk: ${event.finalScore}/100
                    (${event.finalSeverity})
                </strong>

            </div>

        </div>

    `;


    if (isEmpty) {

        incidentTimelineElement.innerHTML =
            newIncident;

    } else {

        incidentTimelineElement.insertAdjacentHTML(
            "afterbegin",
            newIncident
        );

    }

}


// ============================================
// CHART INITIALIZATION
// ============================================

function initializeCharts() {

    const riskCanvas =
        document.getElementById("riskChart");

    const threatCanvas =
        document.getElementById("threatChart");


    if (!riskCanvas || !threatCanvas) {
        console.warn("Chart canvases not found.");
        return;
    }


    riskChart = new Chart(riskCanvas, {

        type: "line",

        data: {

            labels: [],

            datasets: [{

                label: "Risk Score",

                data: [],

                borderWidth: 3,

                tension: 0.35,

                fill: false

            }]

        },

        options: {

            responsive: true,

            maintainAspectRatio: false,

            scales: {

                y: {

                    min: 0,

                    max: 100,

                    ticks: {
                        stepSize: 20
                    }

                }

            },

            plugins: {

                legend: {
                    display: true
                }

            }

        }

    });


    threatChart = new Chart(threatCanvas, {

        type: "doughnut",

        data: {

            labels: [
                "Normal",
                "Medium",
                "High",
                "Critical"
            ],

            datasets: [{

                data: [
                    0,
                    0,
                    0,
                    0
                ],

                borderWidth: 2

            }]

        },

        options: {

            responsive: true,

            maintainAspectRatio: false,

            plugins: {

                legend: {
                    position: "bottom"
                }

            }

        }

    });

}


// ============================================
// UPDATE CHARTS
// ============================================

function updateCharts() {

    updateRiskChart();

    updateThreatChart();

}


// ============================================
// RISK CHART
// ============================================

function updateRiskChart() {

    if (!riskChart) {
        return;
    }


    riskChart.data.labels =
        riskHistory.map(item => item.label);


    riskChart.data.datasets[0].data =
        riskHistory.map(item => item.score);


    riskChart.update();

}


// ============================================
// THREAT DISTRIBUTION
// ============================================

function updateThreatChart() {

    if (!threatChart) {
        return;
    }


    const normalCount =
        events.filter(event =>
            event.finalSeverity === "LOW"
        ).length;


    const mediumCount =
        events.filter(event =>
            event.finalSeverity === "MEDIUM"
        ).length;


    const highCount =
        events.filter(event =>
            event.finalSeverity === "HIGH"
        ).length;


    const criticalCount =
        events.filter(event =>
            event.finalSeverity === "CRITICAL"
        ).length;


    threatChart.data.datasets[0].data = [

        normalCount,

        mediumCount,

        highCount,

        criticalCount

    ];


    threatChart.update();

}


// ============================================
// TIME LABEL
// ============================================

function getTimeLabel() {

    return new Date().toLocaleTimeString(
        [],
        {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        }
    );

}


// ============================================
// ERROR MESSAGE
// ============================================

function showError(message) {

    threatListElement.innerHTML = `

        <div class="empty-state">

            <strong>
                ⚠️ Error
            </strong>

            <br><br>

            ${escapeHTML(message)}

        </div>

    `;

}


// ============================================
// HTML ESCAPE
// ============================================

function escapeHTML(value) {

    if (value === null || value === undefined) {
        return "";
    }


    return String(value)

        .replace(/&/g, "&amp;")

        .replace(/</g, "&lt;")

        .replace(/>/g, "&gt;")

        .replace(/"/g, "&quot;")

        .replace(/'/g, "&#039;");

}