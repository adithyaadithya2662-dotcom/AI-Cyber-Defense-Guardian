// ========================================
// AI CYBER DEFENSE GUARDIAN
// FRONTEND APPLICATION
// ========================================


// ========================================
// API CONFIGURATION
// ========================================

const API_URL =
    "https://flooring-hired-applicants-pets.trycloudflare.com/api/analyze";


// ========================================
// DASHBOARD STATE
// ========================================

let totalEvents = 0;
let criticalThreats = 0;
let highThreats = 0;

let scanNumber = 0;

let riskHistory = [];
let scanLabels = [];

let riskChart = null;
let threatChart = null;


// ========================================
// THREAT COUNTERS
// ========================================

const threatCounts = {

    normal_login: 0,

    failed_login: 0,

    suspicious_login: 0,

    new_ip_login: 0,

    multiple_failed_logins: 0

};


// ========================================
// DOM ELEMENTS
// ========================================

const scanButton =
    document.getElementById("scanButton");

const totalEventsElement =
    document.getElementById("totalEvents");

const criticalThreatsElement =
    document.getElementById("criticalThreats");

const highThreatsElement =
    document.getElementById("highThreats");

const currentRiskElement =
    document.getElementById("currentRisk");

const riskScoreElement =
    document.getElementById("riskScore");

const riskSeverityElement =
    document.getElementById("riskSeverity");

const threatList =
    document.getElementById("threatList");

const aiAnalysis =
    document.getElementById("aiAnalysis");

const recommendations =
    document.getElementById("recommendations");

const incidentTimeline =
    document.getElementById("incidentTimeline");


// ========================================
// INITIALIZE RISK CHART
// ========================================

function initializeRiskChart() {

    const canvas =
        document.getElementById("riskChart");

    if (!canvas) {

        console.error(
            "Risk chart canvas not found."
        );

        return;
    }

    const ctx =
        canvas.getContext("2d");

    riskChart = new Chart(
        ctx,
        {

            type: "line",

            data: {

                labels: [],

                datasets: [

                    {

                        label:
                            "Security Risk Score",

                        data: [],

                        borderWidth: 3,

                        tension: 0.35,

                        fill: true,

                        pointRadius: 5,

                        pointHoverRadius: 7

                    }

                ]

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

                        },

                        title: {

                            display: true,

                            text:
                                "Risk Score"

                        }

                    },

                    x: {

                        title: {

                            display: true,

                            text:
                                "Security Scans"

                        }

                    }

                },

                plugins: {

                    legend: {

                        display: true

                    }

                }

            }

        }
    );

}


// ========================================
// INITIALIZE THREAT CHART
// ========================================

function initializeThreatChart() {

    const canvas =
        document.getElementById("threatChart");

    if (!canvas) {

        console.error(
            "Threat chart canvas not found."
        );

        return;
    }

    const ctx =
        canvas.getContext("2d");

    threatChart = new Chart(
        ctx,
        {

            type: "bar",

            data: {

                labels: [

                    "Normal Login",

                    "Failed Login",

                    "Suspicious Login",

                    "New IP Login",

                    "Multiple Failed"

                ],

                datasets: [

                    {

                        label:
                            "Detected Events",

                        data: [

                            0,
                            0,
                            0,
                            0,
                            0

                        ],

                        borderWidth: 2

                    }

                ]

            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                scales: {

                    y: {

                        beginAtZero: true,

                        ticks: {

                            stepSize: 1

                        },

                        title: {

                            display: true,

                            text:
                                "Number of Events"

                        }

                    },

                    x: {

                        title: {

                            display: true,

                            text:
                                "Threat Category"

                        }

                    }

                },

                plugins: {

                    legend: {

                        display: true

                    }

                }

            }

        }
    );

}


// ========================================
// UPDATE RISK CHART
// ========================================

function updateRiskChart(score) {

    if (!riskChart) {

        return;

    }

    scanNumber++;

    riskHistory.push(score);

    scanLabels.push(
        `Scan ${scanNumber}`
    );

    riskChart.data.labels =
        scanLabels;

    riskChart.data.datasets[0].data =
        riskHistory;

    riskChart.update();

}


// ========================================
// UPDATE THREAT CHART
// ========================================

function updateThreatChart(eventType) {

    if (!threatChart) {

        return;

    }

    if (
        Object.prototype.hasOwnProperty.call(
            threatCounts,
            eventType
        )
    ) {

        threatCounts[eventType]++;

    }

    threatChart.data.datasets[0].data = [

        threatCounts.normal_login,

        threatCounts.failed_login,

        threatCounts.suspicious_login,

        threatCounts.new_ip_login,

        threatCounts.multiple_failed_logins

    ];

    threatChart.update();

}


// ========================================
// GET SEVERITY FROM RISK SCORE
// ========================================
//
// 80 - 100 = CRITICAL
// 60 - 79  = HIGH
// 30 - 59  = MEDIUM
// 0  - 29  = LOW
//
// This is the important fix for HIGH RISK.
//

function getSeverityFromScore(score) {

    score = Number(score) || 0;

    if (score >= 80) {

        return "CRITICAL";

    }

    if (score >= 60) {

        return "HIGH";

    }

    if (score >= 30) {

        return "MEDIUM";

    }

    return "LOW";

}


// ========================================
// RUN SECURITY SCAN
// ========================================

async function runSecurityScan() {

    if (!scanButton) {

        console.error(
            "Scan button not found."
        );

        return;

    }

    scanButton.disabled = true;

    scanButton.textContent =
        "ANALYZING...";

    try {

        const response =
            await fetch(API_URL);

        if (!response.ok) {

            throw new Error(
                `API returned ${response.status}`
            );

        }

        const data =
            await response.json();

        console.log(
            "Security Analysis:",
            data
        );

        updateDashboard(data);

    }

    catch (error) {

        console.error(
            "Security scan failed:",
            error
        );

        showError();

    }

    finally {

        scanButton.disabled = false;

        scanButton.textContent =
            "RUN SECURITY SCAN";

    }

}


// ========================================
// UPDATE DASHBOARD
// ========================================

function updateDashboard(data) {

    // ------------------------------------
    // BASIC VALIDATION
    // ------------------------------------

    if (!data) {

        console.error(
            "No data received from API."
        );

        return;

    }


    // ------------------------------------
    // GET DATA FROM API
    // ------------------------------------

    const finalRisk =
        data.final_risk || {};

    const event =
        data.event || {};


    // ------------------------------------
    // GET RISK SCORE
    // ------------------------------------

    const score =
        Number(
            finalRisk.final_risk_score
        ) || 0;


    // ------------------------------------
    // DETERMINE SEVERITY
    // ------------------------------------
    //
    // IMPORTANT:
    // We calculate severity from the
    // final score so HIGH is never missed.
    //

    const severity =
        getSeverityFromScore(score);


    // ------------------------------------
    // INCREASE TOTAL EVENTS
    // ------------------------------------

    totalEvents++;


    // ------------------------------------
    // UPDATE CRITICAL / HIGH COUNTERS
    // ------------------------------------

    if (severity === "CRITICAL") {

        criticalThreats++;

    }

    else if (severity === "HIGH") {

        highThreats++;

    }


    // ------------------------------------
    // UPDATE TOP DASHBOARD CARDS
    // ------------------------------------

    if (totalEventsElement) {

        totalEventsElement.textContent =
            totalEvents;

    }

    if (criticalThreatsElement) {

        criticalThreatsElement.textContent =
            criticalThreats;

    }

    if (highThreatsElement) {

        highThreatsElement.textContent =
            highThreats;

    }

    if (currentRiskElement) {

        currentRiskElement.textContent =
            score;

    }


    // ------------------------------------
    // UPDATE CURRENT RISK PANEL
    // ------------------------------------

    if (riskScoreElement) {

        riskScoreElement.textContent =
            score;

    }

    if (riskSeverityElement) {

        riskSeverityElement.textContent =
            severity;

    }

    updateRiskColor(
        severity
    );


    // ------------------------------------
    // CREATE CORRECTED DATA
    // ------------------------------------
    //
    // This makes the rest of the dashboard
    // use the same calculated severity.
    //

    const correctedData = {

        ...data,

        final_risk: {

            ...finalRisk,

            final_risk_score:
                score,

            severity:
                severity

        }

    };


    // ------------------------------------
    // UPDATE RISK CHART
    // ------------------------------------

    updateRiskChart(
        score
    );


    // ------------------------------------
    // UPDATE THREAT CHART
    // ------------------------------------

    updateThreatChart(
        event.event_type
    );


    // ------------------------------------
    // UPDATE THREAT MONITOR
    // ------------------------------------

    addThreat(
        correctedData
    );


    // ------------------------------------
    // UPDATE AI ANALYSIS
    // ------------------------------------

    displayAIAnalysis(
        data
    );


    // ------------------------------------
    // UPDATE RECOMMENDATIONS
    // ------------------------------------

    if (
        data.explanation &&
        Array.isArray(
            data.explanation.recommendations
        )
    ) {

        displayRecommendations(
            data.explanation.recommendations
        );

    }


    // ------------------------------------
    // UPDATE TIMELINE
    // ------------------------------------

    addTimelineEvent(
        correctedData
    );


    // ------------------------------------
    // DEBUG LOG
    // ------------------------------------

    console.log(
        "================================"
    );

    console.log(
        "DASHBOARD UPDATED"
    );

    console.log(
        "Risk Score:",
        score
    );

    console.log(
        "Severity:",
        severity
    );

    console.log(
        "Total Events:",
        totalEvents
    );

    console.log(
        "Critical Threats:",
        criticalThreats
    );

    console.log(
        "High Risk:",
        highThreats
    );

    console.log(
        "================================"
    );

}


// ========================================
// RISK COLOR
// ========================================

function updateRiskColor(severity) {

    const riskCircle =
        document.querySelector(
            ".risk-circle"
        );

    if (
        !riskCircle ||
        !riskSeverityElement
    ) {

        return;

    }


    severity =
        String(severity || "")
            .toUpperCase()
            .trim();


    if (severity === "CRITICAL") {

        riskSeverityElement.style.color =
            "#ff3d5a";

        riskCircle.style.borderColor =
            "#ff3d5a";

    }

    else if (severity === "HIGH") {

        riskSeverityElement.style.color =
            "#ff6b35";

        riskCircle.style.borderColor =
            "#ff6b35";

    }

    else if (severity === "MEDIUM") {

        riskSeverityElement.style.color =
            "#ffb300";

        riskCircle.style.borderColor =
            "#ffb300";

    }

    else {

        riskSeverityElement.style.color =
            "#00e676";

        riskCircle.style.borderColor =
            "#00e676";

    }

}


// ========================================
// ADD THREAT
// ========================================

function addThreat(data) {

    const event =
        data.event || {};

    const risk =
        data.final_risk || {};

    const explanation =
        data.explanation || {};


    if (!threatList) {

        return;

    }


    // ------------------------------------
    // REMOVE EMPTY STATE
    // ------------------------------------

    const emptyState =
        threatList.querySelector(
            ".empty-state"
        );

    if (emptyState) {

        emptyState.remove();

    }


    // ------------------------------------
    // CREATE THREAT ITEM
    // ------------------------------------

    const item =
        document.createElement(
            "div"
        );

    item.className =
        "threat-item";


    // ------------------------------------
    // SELECT ICON
    // ------------------------------------

    let icon =
        "🟢";

    if (
        risk.severity === "CRITICAL"
    ) {

        icon =
            "🔴";

    }

    else if (
        risk.severity === "HIGH"
    ) {

        icon =
            "🟠";

    }

    else if (
        risk.severity === "MEDIUM"
    ) {

        icon =
            "🟡";

    }


    // ------------------------------------
    // THREAT TEXT
    // ------------------------------------

    item.innerHTML = `

        <div class="threat-info">

            <div class="threat-icon">

                ${icon}

            </div>

            <div>

                <div class="threat-title">

                    ${
                        explanation.threat_type ||
                        "Security Event"
                    }

                </div>

                <div class="threat-meta">

                    User:
                    ${event.username || "Unknown"}

                    &nbsp; • &nbsp;

                    IP:
                    ${event.ip_address || "Unknown"}

                </div>

                <div class="threat-meta">

                    Event:
                    ${event.event_type || "Unknown"}

                </div>

            </div>

        </div>


        <div class="threat-risk">

            ${
                risk.final_risk_score || 0
            }/100

            <div class="threat-meta">

                ${
                    risk.severity || "LOW"
                }

            </div>

        </div>

    `;


    // ------------------------------------
    // ADD TO TOP OF LIST
    // ------------------------------------

    threatList.prepend(
        item
    );


    // ------------------------------------
    // KEEP MAX 10 EVENTS
    // ------------------------------------

    while (
        threatList.children.length > 10
    ) {

        threatList.removeChild(
            threatList.lastChild
        );

    }

}


// ========================================
// AI ANALYSIS
// ========================================

function displayAIAnalysis(data) {

    if (!aiAnalysis) {

        return;

    }

    const explanation =
        data.explanation || {};


    const reasons =
        Array.isArray(
            explanation.reasons
        )
            ? explanation.reasons
            : [];


    aiAnalysis.innerHTML = `

        <div class="analysis-box">

            <h3>
                🧠 Threat Classification
            </h3>

            <p>

                <strong>

                    ${
                        explanation.threat_type ||
                        "Unknown"
                    }

                </strong>

            </p>

            <p style="margin-top:10px;">

                AI Confidence:

                <strong>

                    ${
                        explanation.confidence ||
                        0
                    }%

                </strong>

            </p>

        </div>


        <div class="analysis-box">

            <h3>
                🔍 Detection Factors
            </h3>

            ${
                reasons
                    .map(
                        reason => `

                            <div class="reason">

                                ${reason}

                            </div>

                        `
                    )
                    .join("")
            }

        </div>

    `;

}


// ========================================
// RECOMMENDATIONS
// ========================================

function displayRecommendations(
    items
) {

    if (!recommendations) {

        return;

    }


    if (
        !items ||
        items.length === 0
    ) {

        recommendations.innerHTML = `

            <div class="empty-state">

                No defensive actions required.

            </div>

        `;

        return;

    }


    recommendations.innerHTML =

        items
            .map(
                item => `

                    <div class="recommendation">

                        ${item}

                    </div>

                `
            )
            .join("");

}


// ========================================
// INCIDENT TIMELINE
// ========================================

function addTimelineEvent(data) {

    if (!incidentTimeline) {

        return;

    }


    const event =
        data.event || {};

    const risk =
        data.final_risk || {};

    const explanation =
        data.explanation || {};


    // ------------------------------------
    // REMOVE EMPTY STATE
    // ------------------------------------

    const emptyState =
        incidentTimeline.querySelector(
            ".empty-state"
        );

    if (emptyState) {

        emptyState.remove();

    }


    // ------------------------------------
    // CREATE TIMELINE ITEM
    // ------------------------------------

    const item =
        document.createElement(
            "div"
        );

    item.className =
        "threat-item";


    item.innerHTML = `

        <div class="threat-info">

            <div class="threat-icon">

                ⏱️

            </div>

            <div>

                <div class="threat-title">

                    ${
                        explanation.threat_type ||
                        "Security Event"
                    }

                </div>

                <div class="threat-meta">

                    ${
                        event.event_type ||
                        "Unknown"
                    }

                    &nbsp; • &nbsp;

                    ${
                        event.username ||
                        "Unknown"
                    }

                </div>

            </div>

        </div>


        <div class="threat-risk">

            ${
                risk.final_risk_score || 0
            }/100

            <div class="threat-meta">

                ${
                    risk.severity || "LOW"
                }

            </div>

        </div>

    `;


    incidentTimeline.prepend(
        item
    );


    // ------------------------------------
    // KEEP MAX 10 EVENTS
    // ------------------------------------

    while (
        incidentTimeline.children.length > 10
    ) {

        incidentTimeline.removeChild(
            incidentTimeline.lastChild
        );

    }

}


// ========================================
// ERROR HANDLING
// ========================================

function showError() {

    if (!threatList) {

        return;

    }


    threatList.innerHTML = `

        <div class="empty-state">

            ❌ Unable to connect to
            the Cyber Defense API.

            <br><br>

            Make sure the public API is running.

            <br><br>

            <strong>

                ${API_URL}

            </strong>

        </div>

    `;

}


// ========================================
// SCAN BUTTON
// ========================================

if (scanButton) {

    scanButton.addEventListener(
        "click",
        runSecurityScan
    );

}


// ========================================
// START APPLICATION
// ========================================

initializeRiskChart();

initializeThreatChart();