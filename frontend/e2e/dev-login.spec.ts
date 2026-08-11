import { expect, test } from "@playwright/test";

test("development persona enters the tenant dashboard", async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/auth/config")) {
      return route.fulfill({
        json: {
          dev_auth_enabled: true,
          dev_personas: [
            { username: "dev-control-owner", label: "Control owner", role: "control_owner", tenant_id: "tenant-1", tenant_name: "Acme Demo" },
          ],
        },
      });
    }
    if (path.endsWith("/context")) {
      return route.fulfill({ json: { tenant: { id: "tenant-1", name: "Acme Demo" }, principal: { name: "Control owner" }, role: "control_owner", permissions: ["evidence.assigned"] } });
    }
    if (path.endsWith("/tenant-admin/")) return route.fulfill({ json: [] });
    return route.fulfill({ json: { results: [], next: null, previous: null } });
  });

  await page.goto("/");
  await page.getByLabel("Local persona").selectOption("dev-control-owner");
  await expect(page.getByRole("heading", { name: "Acme Demo" })).toBeVisible();
  await expect(page.getByText("control_owner", { exact: true })).toBeVisible();
});
