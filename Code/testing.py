from airflow.models import BaseOperator


from gsirt_soc_phishing_historicals.common.statuslabels import StatusLabels
from gsirt_soc_phishing_historicals.hooks.jira import JiraHookWithProxy


class SetStatusLabelOperator(BaseOperator):
    TASK_ID_PREFIX = "set_status_label_"

    def __init__(self, run_config_task_id: str, status_label: str, fail_if_already_applied: bool, *args, **kwargs):
        self._jira_conn_id = kwargs["params"]["jira_instance"]
        self._run_config_task_id = run_config_task_id
        self._status_label = status_label
        self._fail_if_already_applied = fail_if_already_applied

        super().__init__(task_id=self.get_task_id(status_label), *args, **kwargs)

    @classmethod
    def get_task_id(cls, label: str):
        return f"{cls.TASK_ID_PREFIX}{StatusLabels.get_suffix(label)}"

    def execute(self, context):
        ticket_key: str = self.xcom_pull(context=context, task_ids=self._run_config_task_id, key="ticket_key")
        StatusLabels.set_status_label(
            JiraHookWithProxy(jira_conn_id=self._jira_conn_id).get_conn(),
            ticket_key,
            self._status_label,
            fail_if_already_applied=self._fail_if_already_applied,
        )

