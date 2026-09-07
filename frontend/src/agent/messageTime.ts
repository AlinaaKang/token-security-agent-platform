function pad(value: number) {
  return String(value).padStart(2, "0");
}

function dateKey(value: Date) {
  return `${value.getFullYear()}-${value.getMonth()}-${value.getDate()}`;
}

export function formatAgentMessageTime(value: string, now = new Date()) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return { short: "时间未知", full: "时间未知", dateTime: value };
  const clock = `${pad(date.getHours())}:${pad(date.getMinutes())}`;
  const full = `${date.getFullYear()}年${date.getMonth() + 1}月${date.getDate()}日 ${clock}`;
  const yesterday = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1);
  let short: string;
  if (dateKey(date) === dateKey(now)) short = clock;
  else if (dateKey(date) === dateKey(yesterday)) short = `昨天 ${clock}`;
  else if (date.getFullYear() === now.getFullYear()) short = `${date.getMonth() + 1}月${date.getDate()}日 ${clock}`;
  else short = full;
  return { short, full, dateTime: value };
}
