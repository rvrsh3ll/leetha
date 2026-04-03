// frontend/src/main.tsx
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "sonner";
import { ThemeProvider } from "@/providers/theme-provider";
import App from "@/App";
import "@/index.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 5000,        // Data considered fresh for 5 seconds — prevents WS-triggered refetch storms
      refetchInterval: false,  // No automatic polling by default — pages opt in explicitly
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <BrowserRouter>
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <App />
        <Toaster
          position="bottom-right"
          theme="dark"
          toastOptions={{
            duration: 6000,
            classNames: {
              toast: "leetha-toast",
              title: "leetha-toast-title",
              description: "leetha-toast-description",
              success: "leetha-toast-success",
              error: "leetha-toast-error",
              warning: "leetha-toast-warning",
              info: "leetha-toast-info",
            },
          }}
        />
      </ThemeProvider>
    </QueryClientProvider>
  </BrowserRouter>
);
