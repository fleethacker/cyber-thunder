import { request } from './client';
import type { DiscoveryScope, ScopeRangePreview } from './types';

export interface ScopeRecipeInput {
  id: string;
  name: string;
  include: string[] | null;
  exclude: string[] | null;
  allow_public: boolean;
  scanner_target: string | null;
  acknowledge_normalization: boolean;
}
export interface ScopeRecipe extends ScopeRecipeInput {
  networks: string[];
  original_expressions_known: boolean;
}
export interface ScopeRecipeSnapshot {
  revision: string;
  recipes: ScopeRecipe[];
  scopes: DiscoveryScope[];
}
export interface ScopeRecipeRequest {
  revision: string;
  recipes: ScopeRecipeInput[];
}
export interface ScopeRecipePreview {
  revision: string;
  fingerprint: string;
  preview: ScopeRangePreview;
  recipes: { id: string; name: string; preview: ScopeRangePreview }[];
}
export const scopeRecipesApi = {
  load: () => request<ScopeRecipeSnapshot>('GET', '/discovery/scopes/recipes'),
  preview: (body: ScopeRecipeRequest) => request<ScopeRecipePreview>('POST', '/discovery/scopes/recipes/preview', { body }),
  save: (body: ScopeRecipeRequest & { preview_fingerprint: string; reason: string }) =>
    request<ScopeRecipeSnapshot & { preview: ScopeRangePreview }>('PUT', '/discovery/scopes/recipes', { body }),
};
