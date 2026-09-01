const API_URL = "https://musical-alumni-stock-subaru.trycloudflare.com/api/analyze";

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
// RUN SECURITY SCAN
// ========================================

async function runSecurityScan() {

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

    totalEvents++;

    const finalRisk =
        data.final_risk;

    const score =
        finalRisk.final_risk_score;

    const severity =
        finalRisk.severity;

    const event =
        data.event;


    // ====================================
    // UPDATE COUNTERS
    // ====================================

    if (
        severity === "CRITICAL"
    ) {

        criticalThreats++;

    }

    if (
        severity === "HIGH"
    ) {

        highThreats++;

    }

    totalEventsElement.textContent =
        totalEvents;

    criticalThreatsElement.textContent =
        criticalThreats;

    highThreatsElement.textContent =
        highThreats;

    currentRiskElement.textContent =
        score;


    // ====================================
    // CURRENT RISK PANEL
    // ====================================

    riskScoreElement.textContent =
        score;

    riskSeverityElement.textContent =
        severity;

    updateRiskColor(
        severity
    );


    // ====================================
    // UPDATE CHARTS
    // ====================================

    updateRiskChart(
        score
    );

    updateThreatChart(
        event.event_type
    );


    // ====================================
    // THREAT MONITOR
    // ====================================

    addThreat(data);


    // ====================================
    // AI ANALYSIS
    // ====================================

    displayAIAnalysis(
        data
    );


    // ====================================
    // RECOMMENDATIONS
    // ====================================

    if (
        data.explanation &&
        data.explanation.recommendations
    ) {

        displayRecommendations(
            data.explanation.recommendations
        );

    }


    // ====================================
    // TIMELINE
    // ====================================

    addTimelineEvent(
        data
    );

}


// ========================================
// RISK COLOR
// ========================================

function updateRiskColor(
    severity
) {

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

    if (
        severity === "CRITICAL"
    ) {

        riskSeverityElement.style.color =
            "#ff3d5a";

        riskCircle.style.borderColor =
            "#ff3d5a";

    }

    else if (
        severity === "HIGH"
    ) {

        riskSeverityElement.style.color =
            "#ff6b35";

        riskCircle.style.borderColor =
            "#ff6b35";

    }

    else if (
        severity === "MEDIUM"
    ) {

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
        data.event;

    const risk =
        data.final_risk;

    const explanation =
        data.explanation;

    const emptyState =
        threatList.querySelector(
            ".empty-state"
        );

    if (emptyState) {

        emptyState.remove();

    }

    const item =
        document.createElement(
            "div"
        );

    item.className =
        "threat-item";

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

    item.innerHTML = `

        <div class="threat-info">

            <div class="threat-icon">
                ${icon}
            </div>

            <div>

                <div class="threat-title">

                    ${explanation.threat_type}

                </div>

                <div class="threat-meta">

                    User:
                    ${event.username}

                    &nbsp; • &nbsp;

                    IP:
                    ${event.ip_address}

                </div>

                <div class="threat-meta">

                    Event:
                    ${event.event_type}

                </div>

            </div>

        </div>

        <div class="threat-risk">

            ${risk.final_risk_score}/100

            <div class="threat-meta">

                ${risk.severity}

            </div>

        </div>

    `;

    threatList.prepend(
        item
    );

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

    const explanation =
        data.explanation;

    aiAnalysis.innerHTML = `

        <div class="analysis-box">

            <h3>
                🧠 Threat Classification
            </h3>

            <p>

                <strong>
                    ${explanation.threat_type}
                </strong>

            </p>

            <p style="margin-top:10px;">

                AI Confidence:

                <strong>

                    ${explanation.confidence}%

                </strong>

            </p>

        </div>

        <div class="analysis-box">

            <h3>
                🔍 Detection Factors
            </h3>

            ${explanation.reasons.map(
                reason => `

                    <div class="reason">

                        ${reason}

                    </div>

                `
            ).join("")}

        </div>

    `;

}


// ========================================
// RECOMMENDATIONS
// ========================================

function displayRecommendations(
    items
) {

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

        items.map(
            item => `

                <div class="recommendation">

                    ${item}

                </div>

            `
        ).join("");

}


// ========================================
// INCIDENT TIMELINE
// ========================================

function addTimelineEvent(data) {

    const event =
        data.event;

    const risk =
        data.final_risk;

    const explanation =
        data.explanation;

    const emptyState =
        incidentTimeline.querySelector(
            ".empty-state"
        );

    if (emptyState) {

        emptyState.remove();

    }

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

                    ${explanation.threat_type}

                </div>

                <div class="threat-meta">

                    ${event.event_type}

                    &nbsp; • &nbsp;

                    ${event.username}

                </div>

            </div>

        </div>

        <div class="threat-risk">

            ${risk.final_risk_score}/100

            <div class="threat-meta">

                ${risk.severity}

            </div>

        </div>

    `;

    incidentTimeline.prepend(
        item
    );

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

scanButton.addEventListener(
    "click",
    runSecurityScan
);


// ========================================
// START APPLICATION
// ========================================

initializeRiskChart();

initializeThreatChart();