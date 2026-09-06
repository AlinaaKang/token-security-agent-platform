import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ResultGuide } from "./ResultGuide";

afterEach(cleanup);

describe("ResultGuide", () => {
  it("reveals concise result terms without invoking the surrounding workflow", () => {
    const run = vi.fn();
    render(
      <>
        <button type="button" onClick={run}>开始检测</button>
        <ResultGuide
          title="如何理解本次结果"
          summary="这些结论来自当前检测范围。"
          items={[
            { term: "异常候选", explanation: "表示现有证据命中，不代表攻击已经成功。" },
            { term: "工具失败", explanation: "表示没有形成可验证结果。" },
          ]}
        />
      </>,
    );

    const disclosure = screen.getByRole("group", { name: "如何理解本次结果" });
    expect(disclosure).not.toHaveAttribute("open");
    fireEvent.click(screen.getByText("如何理解本次结果"));

    expect(disclosure).toHaveAttribute("open");
    expect(screen.getByText("这些结论来自当前检测范围。")).toBeInTheDocument();
    expect(screen.getByText("异常候选").parentElement).toHaveTextContent("不代表攻击已经成功");
    expect(screen.getByText("工具失败").parentElement).toHaveTextContent("没有形成可验证结果");
    expect(run).not.toHaveBeenCalled();
  });
});
