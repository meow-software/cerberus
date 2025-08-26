import { IsEmail, IsString, Length, MinLength } from 'class-validator';

export class ClientCredentialsDto {
  @Length(18)
  @IsString() clientId: string;
  
  @IsString() 
  @Length(70) 
  clientSecret: string;
}
