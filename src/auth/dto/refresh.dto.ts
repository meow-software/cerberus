import { IsOptional, IsString } from 'class-validator';

export class RefreshDto {
  @IsString() refreshToken: string;
  
  @IsOptional()
  @IsString()
  accessToken?: string;
}
