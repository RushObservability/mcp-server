//! Toolsets group related tools so operators can keep the default tool list
//! small and switch areas on or off with `--toolsets`.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Toolset {
    Core,
    Analysis,
    Alerting,
    Dashboards,
    Changes,
    SavedQueries,
}

impl Toolset {
    pub const ALL: &'static [Toolset] = &[
        Toolset::Core,
        Toolset::Analysis,
        Toolset::Alerting,
        Toolset::Dashboards,
        Toolset::Changes,
        Toolset::SavedQueries,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Toolset::Core => "core",
            Toolset::Analysis => "analysis",
            Toolset::Alerting => "alerting",
            Toolset::Dashboards => "dashboards",
            Toolset::Changes => "changes",
            Toolset::SavedQueries => "saved_queries",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|t| t.name().eq_ignore_ascii_case(name.trim()))
    }

    /// One line used in the server instructions.
    pub fn summary(self) -> &'static str {
        match self {
            Toolset::Core => {
                "core: context, time windows, field discovery, log and span search, aggregation, \
                 traces, services, PromQL and metric discovery, UI links"
            }
            Toolset::Analysis => {
                "analysis: BubbleUp cohort comparison, before/after window comparison, latency \
                 breakdown, log context and full log records"
            }
            Toolset::Alerting => {
                "alerting: monitors (state, events, previews), SLOs (budget, burn) and anomaly events"
            }
            Toolset::Dashboards => {
                "dashboards: search dashboards, read their widgets, and run a widget's query"
            }
            Toolset::Changes => "changes: deploy markers",
            Toolset::SavedQueries => "saved_queries: list and run saved Explore queries",
        }
    }

    /// Tools registered by this toolset. Kept in sync with the routers by a
    /// test in `server.rs`.
    pub fn tools(self) -> &'static [&'static str] {
        match self {
            Toolset::Core => &[
                "get_context",
                "resolve_time",
                "list_fields",
                "list_field_values",
                "search_logs",
                "search_spans",
                "aggregate",
                "get_trace",
                "list_services",
                "get_service",
                "query_metrics",
                "list_metrics",
                "list_metric_labels",
                "get_link",
            ],
            Toolset::Analysis => &[
                "compare_cohorts",
                "compare_windows",
                "get_service_latency",
                "get_log_context",
                "get_log_record",
            ],
            Toolset::Alerting => &[
                "list_monitors",
                "get_monitor",
                "preview_monitor",
                "list_slos",
                "get_slo",
                "list_anomalies",
                "get_anomaly",
            ],
            Toolset::Dashboards => &[
                "search_dashboards",
                "get_dashboard_summary",
                "get_dashboard",
                "get_widget_data",
            ],
            Toolset::Changes => &["list_deploys"],
            Toolset::SavedQueries => &["list_saved_queries", "run_saved_query"],
        }
    }
}
