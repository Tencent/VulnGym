#!/usr/bin/env python3
"""
演示运行脚本 - 生成演示材料
"""
import subprocess
import sys
from pathlib import Path

def run_demo():
    """运行完整演示流程"""
    
    print("=" * 60)
    print("VulnGym 验证系统 - 演示运行")
    print("=" * 60)
    print()
    
    # 确保在正确的目录
    demo_dir = Path(__file__).parent
    project_root = demo_dir.parent
    
    print(f"项目根目录: {project_root}")
    print()
    
    # 1. 运行 Mock 模式
    print("步骤 1/3: 运行 Mock 模式（无需 API key）")
    print("-" * 60)
    
    cmd_mock = [
        sys.executable, "-m", "vulngym_verify_demo",
        "--entries", "public_fixtures/entries.jsonl",
        "--repo-cache", "mock_repo",
        "--advisories", "mock_advisories",
        "--out", "demo/demo_reports.jsonl",
        "--llm", "mock",
        "--bench"
    ]
    
    result = subprocess.run(cmd_mock, cwd=project_root, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print("错误输出:", result.stderr)
    
    if result.returncode != 0:
        print(f"✗ Mock 模式运行失败，退出码 {result.returncode}")
        return False
    
    print("✓ Mock 模式运行成功")
    print()
    
    # 2. 运行测试
    print("步骤 2/3: 运行单元测试")
    print("-" * 60)
    
    cmd_test = [
        sys.executable, "-m", "pytest",
        "tests/test_eval.py",
        "-v",
        "--tb=short",
        "-q"
    ]
    
    result = subprocess.run(cmd_test, cwd=project_root.parent, capture_output=True, text=True)
    # 只显示最后 20 行（避免输出过长）
    lines = result.stdout.split('\n')
    print('\n'.join(lines[-20:]))
    
    if result.returncode != 0:
        print(f"✗ 测试失败，退出码 {result.returncode}")
        return False
    
    print("✓ 测试通过")
    print()
    
    # 3. 生成演示摘要
    print("步骤 3/3: 生成演示摘要")
    print("-" * 60)
    
    reports_file = project_root / "demo" / "demo_reports.jsonl"
    if reports_file.exists():
        import json
        
        reports = []
        with open(reports_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    reports.append(json.loads(line))
        
        print(f"总报告数: {len(reports)}")
        
        verdicts = {"correct": 0, "incorrect": 0, "uncertain": 0}
        for r in reports:
            verdicts[r.get("verdict", "uncertain")] += 1
        
        print(f"  - correct: {verdicts['correct']}")
        print(f"  - incorrect: {verdicts['incorrect']}")
        print(f"  - uncertain: {verdicts['uncertain']}")
        print()
        
        # 显示第一条报告的摘要
        if reports:
            first = reports[0]
            print("第一条报告摘要:")
            print(f"  - entry_id: {first.get('entry_id')}")
            print(f"  - verdict: {first.get('verdict')}")
            print(f"  - summary: {first.get('summary', 'N/A')[:80]}...")
            print()
    
    print("=" * 60)
    print("✓ 演示运行完成！")
    print("=" * 60)
    print()
    print("生成的文件:")
    print(f"  - 验证报告: demo/demo_reports.jsonl")
    print()
    print("下一步:")
    print("  1. 查看 demo/DEMO_SCRIPT.md 了解详细演示流程")
    print("  2. 查看 docs/DESIGN.md 了解系统设计")
    print("  3. 运行 'pytest tests/ -v' 查看全部测试")
    print()
    
    return True

if __name__ == "__main__":
    success = run_demo()
    sys.exit(0 if success else 1)
